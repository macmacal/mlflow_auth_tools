# MLflow auth tools
This collection of tools allows for MLflow basic auth management.

## Usage
1. Provide the local admin credentials by:

   - The  `./config.yaml` file:
   ```yaml
   MLFLOW_TRACKING_USERNAME: admin
   MLFLOW_TRACKING_PASSWORD: password
   tracking_uri: http://localhost:5000/
   ```
   - Launch args:
   ```bash
    ./mlflow_auth_tools.py --mlflow-username admin --mlflow-password password [...]
   ```

   - By setting environment variables:
   ```bash
   export MLFLOW_TRACKING_USERNAME=admin
   export MLFLOW_TRACKING_PASSWORD=password
   ./mlflow_auth.tools.py [...]
   ```

2. Provide the tracking uri of the MLflow instance via `config.yaml` file (see above) or by launch arg `--tracking-uri http://localhost:5000/`.
3. Access one of the auth commands, type `--help` for more info.


## Sources

- Based on [MLflow Docs](https://www.mlflow.org/docs/latest/auth/index.html#overview).
- All commands are just wrappers for [AuthServiceClient](https://github.com/mlflow/mlflow/blob/master/mlflow/server/auth/client.py) or for [MlflowClient](https://github.com/mlflow/mlflow/blob/21dfada017dc1574b5d45076d72d7afd2a82cbaf/mlflow/tracking/client.py#L79).
