#!/bin/python3
import os
import argparse
import yaml
from getpass import getpass
from collections.abc import Callable
from dataclasses import dataclass

try:
    from mlflow import MlflowClient
    from mlflow.server import get_app_client
    from mlflow.server.auth.client import AuthServiceClient
except ImportError:
    print("ERROR: Can't import mlflow package. Install it with `pip install mlflow`.")
    exit()


@dataclass
class Config:
    tracking_uri: str
    user: str
    password: str
    permission: str
    experiment_name: str
    mlflow_client: MlflowClient
    mlflow_auth_client: AuthServiceClient


def cmd_create_user(cfg: Config):
    if cfg.user is None:
        cfg.user = input("> Enter new user name: ")
    if cfg.password is None:
        cfg.password = getpass("> Enter new password: ")

    cfg.mlflow_auth_client.create_user(
        username=cfg.user,
        password=cfg.password,
    )


def cmd_create_experiment(cfg: Config):
    if cfg.experiment_name is None:
        cfg.experiment_name = input("> Enter experiment name: ")

    cfg.mlflow_client.create_experiment(name=cfg.experiment_name)


def cmd_remove_user(cfg: Config):
    if cfg.user is None:
        cfg.user = input("> Enter user name: ")

    cfg.mlflow_auth_client.delete_user(username=cfg.user)


def cmd_set_password(cfg: Config):
    if cfg.user is None:
        cfg.user = input("> Enter user name: ")
    if cfg.password is None:
        cfg.password = getpass("> Enter new password: ")

    cfg.mlflow_auth_client.update_user_password(
        username=cfg.user,
        password=cfg.password,
    )


def cmd_enable_admin(cfg: Config):
    if cfg.user is None:
        cfg.user = input("> Enter user name: ")

    cfg.mlflow_auth_client.update_user_admin(
        username=cfg.user,
        is_admin=True,
    )


def cmd_disable_admin(cfg: Config):
    if cfg.user is None:
        cfg.user = input("> Enter user name: ")

    cfg.mlflow_auth_client.update_user_admin(
        username=cfg.user,
        is_admin=False,
    )


def cmd_get_user(cfg: Config):
    if cfg.user is None:
        cfg.user = input("> Enter user name: ")

    msg = cfg.mlflow_auth_client.get_user(username=cfg.user)
    print(f"> Result: {msg}")


def cmd_get_experiment(cfg: Config):
    if cfg.experiment_name is None:
        cfg.experiment_name = input("> Enter experiment name: ")

    msg = cfg.mlflow_client.get_experiment_by_name(name=cfg.experiment_name)
    print(f"> Result: {msg}")


def cmd_add_user_permission(cfg: Config):
    if cfg.user is None:
        cfg.user = input("> Enter user name: ")
    if cfg.experiment_name is None:
        cfg.experiment_name = input("> Enter experiment name: ")
    if cfg.permission is None:
        cfg.permission = input("> Enter permission (e.g. MANAGE): ")

    try:
        cfg.mlflow_auth_client.create_experiment_permission(
            experiment_id=cfg.experiment_name,
            username=cfg.user,
            permission=cfg.permission,
        )
    except Exception:
        cfg.mlflow_auth_client.update_experiment_permission(
            experiment_id=cfg.experiment_name,
            username=cfg.user,
            permission=cfg.permission,
        )


def cmd_remove_user_permission(cfg: Config):
    if cfg.user is None:
        cfg.user = input("> Enter user name: ")
    if cfg.experiment_name is None:
        cfg.experiment_name = input("> Enter experiment name: ")

    cfg.mlflow_auth_client.delete_experiment_permission(
        experiment_id=cfg.experiment_name,
        username=cfg.user,
    )


COMMANDS: dict[str, Callable] = {
    "create-user": cmd_create_user,
    "create-experiment": cmd_create_experiment,
    "remove-user": cmd_remove_user,
    "set-password": cmd_set_password,
    "enable-admin": cmd_enable_admin,
    "disable-admin": cmd_disable_admin,
    "get-user": cmd_get_user,
    "get-experiment": cmd_get_experiment,
    "add-user-permission": cmd_add_user_permission,
    "remove-user-permission": cmd_remove_user_permission,
}


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c" "--command",
        default="get-users",
        choices=COMMANDS.keys(),
        required=True,
        help="select command for interacting with MLflow basic auth",
    )
    parser.add_argument("-u", "--user", type=str, default=None, help="user name")
    parser.add_argument("-p", "--password", type=str, default=None, help="user password")
    parser.add_argument("-e", "--experiment-name", type=str, default=None, help="experiment name")
    parser.add_argument("-t", "--tracking-uri", type=str, default=None, help="tracking uri")
    # TODO: add options from MLFlow
    parser.add_argument("--perrmision", type=str, default=None, help="user permission")
    parser.add_argument(
        "--mlflow-username",
        type=str,
        default=None,
        help="overwrites MLFLOW_TRACKING_USERNAME",
    )
    parser.add_argument(
        "--mlflow-password",
        type=str,
        default=None,
        help="overwrites MLFLOW_TRACKING_PASSWORD",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        cfg_yaml = yaml.safe_load("config.yaml")
        tracking_uri = cfg_yaml["tracking_uri"]
        mlflow_username = cfg_yaml["MLFLOW_TRACKING_USERNAME"]
        mlflow_password = cfg_yaml["MLFLOW_TRACKING_PASSWORD"]
    except Exception:
        print("> Failed to load config.yaml. Falling back to launch arguments.")
        try:
            if args.tracking_uri is None:
                raise ValueError
            tracking_uri = args.tracking_uri
        except ValueError:
            print("> ERROR: No tracking_uri has been provided.")
            exit()
        try:
            if args.mlflow_username is None:
                raise ValueError
            mlflow_username = args.mlflow_username
        except ValueError:
            print(
                "> WARNING: No MLFLOW USERNAME for auth has been provided. Falling back to the 'MLFLOW_TRACKING_USERNAME' env variable."
            )
            try:
                mlflow_username = os.environ["MLFLOW_TRACKING_USERNAME"]
            except KeyError:
                print("> ERROR: No MLFLOW_TRACKING_USERNAME has been provided.")
                exit()
        try:
            if args.mlflow_password is None:
                raise ValueError
            mlflow_password = args.mlflow_password
        except ValueError:
            print(
                "> WARNING: No MLFLOW PASSWORD for auth has been provided. Falling back to the 'MLFLOW_TRACKING_PASSWORD' env variable."
            )
            try:
                mlflow_password = os.environ["MLFLOW_TRACKING_PASSWORD"]
            except KeyError:
                print("> ERROR: No MLFLOW_TRACKING_PASSWORD has been provided.")
                exit()

    print(f"> Will authenticate as: {mlflow_username}")
    os.environ["MLFLOW_TRACKING_USERNAME"] = mlflow_username
    os.environ["MLFLOW_TRACKING_PASSWORD"] = mlflow_password

    cfg = Config(
        tracking_uri=tracking_uri,
        user=args.user,
        password=args.password,
        experiment_name=args.experiment_name,
        mlflow_auth_client=get_app_client("basic-auth", tracking_uri=tracking_uri),
        mlflow_client=MlflowClient(tracking_uri=tracking_uri),
    )

    try:
        cmd = COMMANDS[args.command]
        cmd(cfg)
        print(f"> {args.command} - Done.")
    except Exception as e:
        print(f"> An exception occurred: {e}")


if __name__ == "__main__":
    main()
