# Inji Verify – Docker Compose Setup

- **Docker**

  - [Install on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
  - [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
  - [Other platforms](https://docs.docker.com/engine/install/)

- **Docker Compose**

  `Note: Requires installation of Docker. This step can be skippped if Docker desktop(Windows) is installed as it comes along with docker compose. Please install Docker using above links before proceeding for the installation of docker compose`

  - [Install as plugin to docker command](https://docs.docker.com/compose/install/#scenario-two-install-the-compose-plugin)
  - [Install the Compose standalone](https://docs.docker.com/compose/install/#scenario-three-install-the-compose-standalone)

Once installed, use Docker compose option below to run the Inji Verify application for a quick demo.

---

## Setup


### WebWallets Configuration

The `WebWallets` array in `config/config.json` defines the web wallet(s) available for the Same Device VP flow.

```json
"WebWallets": [
  {
    "id": "inji-wallet",
    "name": "Inji Wallet",
    "iconUrl": "/assets/inji-web-wallet-icon.svg",
    "walletBaseUrl": "https://injiweb.dev-int-inji.mosip.net"
  }
]
```

> **External dependency:** The default `walletBaseUrl` (`https://injiweb.dev-int-inji.mosip.net`) points to a shared **dev/integration** instance of Inji Web Wallet hosted by MOSIP. Wallet flows will **silently fail** if this host is unavailable, retired, or unreachable from your network.

**Before running locally**, replace `walletBaseUrl` with one of the following:

| Scenario | `walletBaseUrl` value |
|---|---|
| Own deployed Inji Web Wallet | `https://<your-inji-web-wallet-host>` |
| Local Inji Web Wallet (default port) | `http://localhost:3001` |
| Mock / disable the entry | remove the entry from the array |

```json
"WebWallets": [
  {
    "id": "inji-wallet",
    "name": "Inji Wallet",
    "iconUrl": "/assets/inji-web-wallet-icon.svg",
    "walletBaseUrl": "http://localhost:3001"
  }
]
```

See [Inji Web Wallet](https://github.com/mosip/inji-web) for instructions on running your own instance.

---

### OpenID4VP config

The configuration file can be found under `config` directory.

**Example Configuration Explanation**

Let's look at the "MOSIP ID" example to understand how these properties work together:

```json
{
  "logo": "/assets/cert.png",
  "name": "MOSIP ID",
  "type": "MOSIPVerifiableCredential",
  "essential": true,
  "clientIdScheme":"did",
  "definition": {
    "purpose": "Relying party is requesting your digital ID for the purpose of Self-Authentication",
    "format": {
      "ldp_vc": {
        "proof_type": [
          "RsaSignature2018"
        ]
      }
    },
    "input_descriptors": [
      {
        "id": "id card credential",
        "format": {
          "ldp_vc": {
            "proof_type": [
              "RsaSignature2018"
            ]
          }
        },
        "constraints": {
          "fields": [
            {
              "path": [
                "$.type"
              ],
              "filter": {
                "type": "object",
                "pattern": "MOSIPVerifiableCredential"
              }
            }
          ]
        }
      }
    ]
  }
}
```
`logo`: The image /assets/cert.png will be shown on the credential selection panel.

`name`: The name that has to be shown on the credential selection panel.

`type`: Internally, this configuration is used to identify what are the different types of credential.

`essential`: This credential is required for the verification to succeed.

`clientIdScheme: did`: The corresponding VP request will use `client_id_scheme` as `DID` and Auth Request will be available to wallet via Request_Uri within the VP request.

`clientIdScheme: pre_registered`: The corresponding VP request will use `client_id_scheme` as `pre_registered` and Auth Request will be available to wallet directly within the VP request.

`definition` : The presentation definition for the particular type of credential. For more details check [[DIF.PresentationExchange]](https://identity.foundation/presentation-exchange/spec/v2.0.0/)

---

### OpenID4VP Setting Up Proxy For Localhost

To get the OpenID4VP flow working locally, use a proxy service like ngrok or localtunnel 
to create a proxy url like https://proxyurl.ngrok.app for http://localhost:3000.

This is required since wallet running on your mobile / tablet device, will not be able to invoke the http://localhost:3000 url,
while sharing the credentials.

#### In docker-compose.yml file replace `VERIFY_SERVICE_PROXY_FOR_LOCALHOST` with `proxyurl.ngrok.app`. 
Save the `docker-compose.yml` file.

### Cross Device Flow

To test the Cross Device flow on your mobile / tablet device, scan the VP request QR code directly.
For Credentials which use `client_id_scheme` as`pre_registered` in the VP request, the wallet will not be able to share the VC since
your locally running Verify application will not be pre registered with the wallet. 
For other Credentials which use `client_id_scheme` as `DID` in the VP request, the wallet will be able to share the VC. 
For `pre_registered`, we should add our client_id into `mimoto-trusted-verifiers.json` which is referred by Inji Wallet.

### Same Device Flow

To test the Same Device flow on your mobile / tablet device, hit the URL https://proxyurl.ngrok.app. 
This will open app. 

---

## Run Using Docker Compose:

Navigate to the docker-compose directory:

<<<<<<< HEAD
```shell
=======
## Why?

Mobile devices cannot access `localhost`.

## Solution:

```bash
ngrok http 3000
```

Example:

```
https://abc123.ngrok.app → http://localhost:3000
```

## Update docker-compose.yml

Replace:

```
VERIFY_SERVICE_PROXY_FOR_LOCALHOST
```

With:

```
abc123.ngrok.app
```

---

# 📱 Flows

## Cross Device Flow

To test the cross-device flow on a mobile or tablet device, scan the VP request QR code directly. For credentials with `clientIdPrefix` set to `pre_registered`, the wallet cannot share the VC unless the locally running Verify application is registered as a trusted verifier. For credentials with `clientIdPrefix` set to `decentralized_identifier`, the wallet can share the VC. For `pre_registered`, add the client ID to `mimoto-trusted-verifiers.json`, which Inji Wallet uses as its trusted verifier list.

### Behavior:

* `decentralized_identifier` → Works directly
* `pre_registered` → Needs trusted verifier config

---

## Same Device Flow

To test the Same Device flow on your mobile / tablet device, hit the URL https://proxyurl.ngrok.app. This will open the app.

> **Note:** VP submission is disabled by default (`VP_SUBMISSION_SUPPORTED=false`). Set it to `true` in `docker-compose.yml` to enable the OpenID4VP tab.

---

# 🐳 Docker Commands

## Start

```bash
docker compose up -d
```

## Stop

```bash
docker compose down
```

## Reset (with volumes)

```bash
docker compose down -v
```

## Logs

```bash
docker compose logs -f
```

---

# 🛠 Local Development

## 1. Enable Local Build

```yaml
verify-service:
  #image: injistackdev/inji-verify-service:develop  
  build:
    context: ../verify-service
  image: inji-verify-service:local    
verify-ui:
  #image: injistackdev/inji-verify-ui:develop
  build:
    context: ../verify-ui
  image: inji-verify-ui:local    
```

---

## 2. Build verify-service locally first

`verify-service`'s Dockerfile does **not** run Maven — it only packages a jar that must already
exist in `verify-service/target/`. Unlike `verify-ui` (whose Dockerfile builds the React app from
source), `docker compose build` will silently reuse whatever's already in `target/` if you skip
this step, including a stale jar from before your latest changes.

> **Never `cd verify-service` and build it standalone.** It depends on the sibling `verify-core`
> module; building it alone resolves `verify-core` from your `~/.m2` cache instead of current
> source, which silently uses a **stale** `verify-core` jar if it's changed since your last
> install — producing confusing `NoClassDefFoundError`s at container startup that don't reproduce
> locally. Always build from the repo root.

```bash
cd inji-verify   # repo root
mvn clean install -Dgpg.skip   # builds + installs verify-core and verify-service together
```

## 3. Clear Cache and Start Docker Compose

```bash
>>>>>>> 73095bd4 (#2148 split into two components verify-core and verify-service (#2231))
cd docker-compose
```

> Make sure ports 3000, 8080, and 5432 are free.

Run the following command to build and start all services:

```shell
docker-compose up -d # if docker compose is installed as a standalone command.
docker compose up -d # if docker compose is installed as a plugin to docker command
```

This will start:

* verify-service (backend)
* verify-ui (frontend)
* postgres (database)

The UI will be accessible at: http://localhost:3000

API (verify-service) swagger runs at: http://localhost:8080/v1/verify/swagger-ui/index.html

To stop the application, run the following command:

```shell
docker-compose down # if docker compose is installed as a standalone command.
docker compose down # if docker compose is installed as a plugin to docker command
```

To remove volumes as well (clean reset):

```shell
docker-compose down -v # if docker compose is installed as a standalone command.
docker compose down -v # if docker compose is installed as a plugin to docker command
```
---
### Troubleshooting

To check container logs:

```shell
docker-compose logs -f
```
