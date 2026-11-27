"""Provision private TLS configuration for the unmodified PostgreSQL entrypoint."""

from scripts.infrastructure.manage import Config, service_image


def prepare_bind(config: Config) -> None:
    from scripts.database.manage import workdir
    from scripts.hardening.runtime_images import IMAGES, ensure
    from scripts.infrastructure.storage import helper, path, prepare

    image = service_image(config, "cve-postgres", IMAGES["postgres"][0])
    ensure(image)
    source = workdir(config) / "tls"
    paths = [source / name for name in ("ca.crt", "server.crt", "server.key")]
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError("Provision database TLS files before starting PostgreSQL")
    prepare(config, ["cve-postgres"])
    # Upstream Alpine and Debian use different postgres UIDs. The entrypoint
    # repairs PGDATA itself, but must also be able to traverse its bind parents.
    helper(
        config,
        ["type=bind,source=" + str(path(config, "postgres_data")) + ",target=/data"],
        "chown postgres:postgres /data; "
        "if [ -d /data/18 ]; then chown postgres:postgres /data/18; fi",
        image=image,
    )
    target = path(config, "postgres_tls")
    helper(
        config,
        [
            "type=bind,source=" + str(source.resolve()) + ",target=/source,readonly",
            "type=bind,source=" + str(target) + ",target=/tls",
        ],
        "cp /source/ca.crt /source/server.crt /source/server.key /tls/; "
        "chown -R postgres:postgres /tls; chmod 700 /tls; chmod 600 /tls/*",
        image=image,
    )
