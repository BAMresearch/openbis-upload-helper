# Local openBIS 7.x Docker Instance

This document describes how to operate the local openBIS 7.x test instance used for development of the **openBIS Upload Helper**.

The instance is expected to live in:

```bash
~/openbis-7-test
```

and to be started from a `compose.yaml` in that directory.

## Local instance

Default development URL:

```text
https://local.openbis.ch/openbis
```

Development credentials:

```text
Username: admin
Password: test
```

These credentials are intended only for the isolated local test instance. Do not reuse them for any non-local deployment.

The current test setup contains at least:

- Space: `TEST`
- Object type: `TEST_SAMPLE`

## Start the instance

Move to the Compose directory:

```bash
cd ~/openbis-7-test
```

Start all services in the background:

```bash
docker compose up -d
```

This starts the PostgreSQL database, openBIS application container, and local ingress.

Check their state:

```bash
docker compose ps
```

The relevant containers should be running, typically:

```text
openbis-db
openbis-app
openbis-ingress
```

openBIS can take some time to become available after the containers start. The containers may be running before the application itself is ready.

## Stop the instance

Stop the containers while preserving them and all persistent data:

```bash
docker compose stop
```

Start the same stopped containers again with:

```bash
docker compose start
```

For normal development, `stop` and `start` are sufficient.

## Stop and remove the containers

To stop and remove the Compose containers and network while preserving the named volumes:

```bash
docker compose down
```

Start them again later with:

```bash
docker compose up -d
```

The openBIS database and stored data remain available because the named Docker volumes are not removed.

## Restart

Restart all running services:

```bash
docker compose restart
```

Restart only openBIS:

```bash
docker compose restart openbis-app
```

Restart only the ingress:

```bash
docker compose restart openbis-ingress
```

## VM reboot behavior

The Compose configuration uses:

```yaml
restart: unless-stopped
```

Therefore, if the VM is shut down or rebooted while the containers are running, Docker should start them again automatically when the VM boots.

Check that Docker itself starts at boot:

```bash
sudo systemctl is-enabled docker
```

Expected:

```text
enabled
```

If the containers were explicitly stopped with:

```bash
docker compose stop
```

they remain stopped after reboot because the policy is `unless-stopped`.

## Check whether openBIS is ready

Test the openBIS application through the ingress:

```bash
curl -vk https://local.openbis.ch/openbis/webapp/eln-lims/version.txt
```

A successful response should return HTTP `200`.

If a `503 Service Unavailable` appears immediately after startup, wait for openBIS to finish initializing and try again.

The ingress may initially report its backends as `DOWN` and then later as `UP`.

## Check openBIS directly inside the container

To bypass the ingress and verify the application server itself:

```bash
docker exec openbis-app curl -v http://localhost:8080/openbis/webapp/eln-lims/version.txt
```

A `200 OK` here means the openBIS application server is healthy.

## Logs

### Database logs

```bash
docker compose logs openbis-db --tail=100
```

Follow them continuously:

```bash
docker compose logs -f openbis-db
```

### Ingress logs

```bash
docker compose logs openbis-ingress --tail=100
```

Follow them continuously:

```bash
docker compose logs -f openbis-ingress
```

During startup it is normal to briefly see messages such as:

```text
Server openbis_as/as is DOWN
```

followed later by:

```text
Server openbis_as/as is UP
```

The same applies to DSS and AFS.

### openBIS application logs

The openBIS image writes its main logs under `/var/log/openbis`.

List available log files:

```bash
docker exec openbis-app   find /var/log/openbis -type f -printf '%p\n'
```

Inspect the tail of all log files:

```bash
docker exec openbis-app bash -c   'find /var/log/openbis -type f -exec sh -c "echo === \$1 ===; tail -n 80 \$1" _ {} \;'
```

## Enter a container

Open a shell in the openBIS application container:

```bash
docker exec -it openbis-app bash
```

Exit with:

```bash
exit
```

For PostgreSQL:

```bash
docker exec -it openbis-db bash
```

## Check PostgreSQL

```bash
docker exec openbis-db pg_isready -U postgres
```

A healthy database should report that it is accepting connections.

## Personal Access Tokens (PATs)

The local instance is intended to support both:

- username/password authentication
- Personal Access Token authentication

PAT configuration is stored in the openBIS Application Server configuration. The relevant settings are:

```properties
personal-access-tokens-enabled = true
personal-access-tokens-file-path = /data/openbis/personal-access-tokens.json
```

The token file is under `/data/openbis` so it resides in persistent openBIS data.

Never commit a real PAT to Git.

## Inspect persistent Docker volumes

```bash
docker volume ls | grep openbis
```

The Compose deployment uses named volumes for the database, openBIS data/configuration, and logs.

## Completely reset the test instance

**Warning: this deletes the local openBIS database and all persistent openBIS data.**

```bash
cd ~/openbis-7-test
docker compose down -v
```

After this command, starting the Compose project again creates a fresh instance:

```bash
docker compose up -d
```

Use `down -v` only when an intentional full reset is wanted.

## Typical daily workflow

Start:

```bash
cd ~/openbis-7-test
docker compose up -d
docker compose ps
```

Check readiness:

```bash
curl -vk https://local.openbis.ch/openbis/webapp/eln-lims/version.txt
```

Develop/test the application.

When finished:

```bash
docker compose stop
```

To resume later:

```bash
cd ~/openbis-7-test
docker compose start
```

If the VM has simply been rebooted and the containers were not explicitly stopped, first check:

```bash
docker compose ps
```

They may already be running.
