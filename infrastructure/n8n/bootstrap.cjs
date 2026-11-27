'use strict';

// These are the import/publication services of the digest-pinned vendor distribution.
// Initialize them once, then let the unchanged vendor entrypoint start the server.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { isDeepStrictEqual } = require('node:util');
const { createHash } = require('node:crypto');

const vendorRoot = '/usr/local/lib/node_modules/n8n';
const vendor = createRequire(path.join(vendorRoot, 'package.json'));
const workflowDirectory = '/opt/cve-workflows';
const credentialFile = '/run/cve-n8n/credentials.json';
const stateFile = '/home/node/.n8n/cve-bootstrap-state.json';
const fingerprint = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function definitions(directory = workflowDirectory) {
  const seen = new Set();
  const workflows = fs.readdirSync(directory).filter(name => name.endsWith('.json')).sort()
    .map(name => JSON.parse(fs.readFileSync(path.join(directory, name), 'utf8')));
  if (workflows.length === 0) throw new Error('No repository workflows found');
  for (const workflow of workflows) {
    if (typeof workflow.id !== 'string' || !workflow.id || seen.has(workflow.id)
        || !Array.isArray(workflow.nodes) || typeof workflow.connections !== 'object'
        || workflow.connections === null || Array.isArray(workflow.connections)) {
      throw new Error('Invalid or duplicate repository workflow definition');
    }
    seen.add(workflow.id);
  }
  return workflows;
}

// Publish literal sub-workflow dependencies before their parents, as n8n requires.
function publicationOrder(workflows) {
  const managed = new Map(workflows.map(workflow => [workflow.id, workflow]));
  const visiting = new Set();
  const complete = new Set();
  const ordered = [];
  function visit(workflow) {
    if (complete.has(workflow.id)) return;
    if (visiting.has(workflow.id)) throw new Error('Cyclic managed sub-workflow references');
    visiting.add(workflow.id);
    for (const node of workflow.nodes) {
      if (node.disabled || node.type !== 'n8n-nodes-base.executeWorkflow') continue;
      const parameters = node.parameters || {};
      if (parameters.source && parameters.source !== 'database') continue;
      const reference = typeof parameters.workflowId === 'object'
        ? parameters.workflowId?.value : parameters.workflowId;
      if (reference !== workflow.id && managed.has(reference)) visit(managed.get(reference));
    }
    visiting.delete(workflow.id);
    complete.add(workflow.id);
    ordered.push(workflow);
  }
  for (const workflow of workflows) visit(workflow);
  return ordered;
}

async function synchronize() {
  // Validate every input before importing anything.
  const workflows = publicationOrder(definitions());
  const credentials = JSON.parse(fs.readFileSync(credentialFile, 'utf8'));
  if (!Array.isArray(credentials) || !credentials.length
      || credentials.some(item => typeof item.id !== 'string' || !item.id || !item.data)
      || new Set(credentials.map(item => item.id)).size !== credentials.length) {
    throw new Error('Invalid managed credential manifest');
  }
  const version = vendor('./package.json').version;
  if (version !== '2.48.8') throw new Error('n8n bootstrap requires the tested pinned version');
  vendor('reflect-metadata');
  vendor('./dist/config');
  const { Container } = vendor('@n8n/di');
  const { CommandRegistry } = vendor('./dist/command-registry.js');
  const { ModuleRegistry } = vendor('@n8n/backend-common');
  Container.get(CommandRegistry); // Register the vendor's packaged modules and CLI schema helpers.
  await Container.get(ModuleRegistry).loadModules();
  const { ImportWorkflowsCommand } = vendor('./dist/commands/import/workflow.js');
  const { ImportCredentialsCommand } = vendor('./dist/commands/import/credentials.js');
  const { WorkflowRepository, CredentialsRepository, AuthRolesService } = vendor('@n8n/db');
  const { CliWorkflowPublisher } = vendor('./dist/commands/cli-workflow-publisher.js');

  const importer = new ImportWorkflowsCommand();
  importer.needsExpressionEngine = true;
  try {
    // The same initialization used by n8n's CLI also migrates a fresh database.
    await importer.init();
    await importer.initExternalHooks();
    // A fresh n8n schema needs the same built-in scopes as a normal server start.
    await Container.get(AuthRolesService).init();
    const previous = fs.existsSync(stateFile)
      ? JSON.parse(fs.readFileSync(stateFile, 'utf8'))
      : { version: 1, workflows: {}, credentials: {} };
    if (previous.version !== 1 || !previous.workflows || !previous.credentials) {
      throw new Error('Invalid private bootstrap state');
    }
    const next = { version: 1, workflows: {}, credentials: {} };
    const repository = Container.get(WorkflowRepository);
    const credentialRepository = Container.get(CredentialsRepository);
    const workspace = fs.mkdtempSync('/tmp/cve-bootstrap-');
    try {
      const changedCredentials = [];
      for (const credential of credentials) {
        const digest = fingerprint(credential);
        const stored = await credentialRepository.findOneBy({ id: credential.id });
        if (!stored || stored.type !== credential.type || previous.credentials[credential.id] !== digest) {
          changedCredentials.push(credential);
        }
        next.credentials[credential.id] = digest;
      }
      if (changedCredentials.length) {
        const input = path.join(workspace, 'credentials.json');
        fs.writeFileSync(input, JSON.stringify(changedCredentials), { mode: 0o600 });
        const credentialImporter = new ImportCredentialsCommand();
        credentialImporter.flags = { input, separate: false };
        await credentialImporter.run();
      }
      for (const credential of credentials) {
        const stored = await credentialRepository.findOneBy({ id: credential.id });
        if (!stored || stored.type !== credential.type) {
          throw new Error('Managed credential import is incomplete');
        }
      }
      const changedWorkflows = [];
      const input = path.join(workspace, 'workflows');
      fs.mkdirSync(input, { mode: 0o700 });
      for (const workflow of workflows) {
        const digest = fingerprint(workflow);
        const stored = await repository.findOneBy({ id: workflow.id });
        if (!stored || previous.workflows[workflow.id] !== digest) {
          changedWorkflows.push({ workflow, publish: !stored || stored.active });
          fs.writeFileSync(path.join(input, fingerprint(workflow.id) + '.json'),
            JSON.stringify(workflow), { mode: 0o600 });
        }
        next.workflows[workflow.id] = digest;
      }
      if (changedWorkflows.length) {
        importer.flags = { input, separate: true, activeState: 'false' };
        await importer.run();
      }
      for (const { workflow, publish } of changedWorkflows) {
        const stored = await repository.findOneBy({ id: workflow.id });
        if (!stored || stored.name !== workflow.name
            || !isDeepStrictEqual(stored.nodes, workflow.nodes)
            || !isDeepStrictEqual(stored.connections, workflow.connections)) {
          throw new Error('Repository workflow import is incomplete: ' + workflow.id);
        }
        // Preserve deliberate disabling, including when a repository definition changes.
        if (publish) {
          await Container.get(CliWorkflowPublisher).publish(workflow.id);
          const published = await repository.findOneBy({ id: workflow.id });
          if (!published.active || published.activeVersionId !== published.versionId) {
            throw new Error('Repository workflow publication failed: ' + workflow.id);
          }
        }
      }
      const pending = stateFile + '.' + process.pid + '.new';
      fs.writeFileSync(pending, JSON.stringify(next), { mode: 0o600, flag: 'wx' });
      fs.renameSync(pending, stateFile);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
    console.log('[cve-n8n] Repository workflows synchronized and published: ' + workflows.length);
    await importer.finally();
  } catch (error) {
    // Do not dump credential inputs or vendor exception payloads into container logs.
    console.error('[cve-n8n] Workflow synchronization failed; server startup aborted.');
    const frames = typeof error.stack === 'string'
      ? error.stack.split('\n').filter(line => /^\s+at /.test(line)).slice(0, 4) : [];
    console.error(JSON.stringify({event: 'workflow_initialization_failed', frames}));
    await importer.finally(new Error('Repository workflow initialization failed'));
    throw error;
  }
}

if (require.main === module) {
  synchronize().catch(() => {
    console.error('[cve-n8n] Workflow bootstrap failed; check repository definitions and private configuration.');
    process.exit(1);
  });
}
module.exports = { definitions, publicationOrder, synchronize };
