"""Developpement Manager for microrepos on github"""
__version__ = "0.5.0"

import shutil
from typing import Any
from collections.abc import Iterable
from typing import Literal
import platform
import subprocess
import os
import click
import git
import getpass
import github
import virtualenv
import tox
from tox.tox_env.python.pip import req_file
from unittest import mock
import requests
import itertools as it
import asyncio


class NonSortedPythonDeps(req_file.PythonDeps):
    # We need something to manage editable order
    def _parse_requirements(
        self,
        opt: req_file.Namespace,
        recurse: bool,
    ) -> list[req_file.ParsedRequirement]:
        result, found = [], set()
        for parsed_line in self._parse_and_recurse(
            str(self._path),
            self.is_constraint,
            recurse,
        ):
            if parsed_line.is_requirement:
                parsed_req = self._handle_requirement_line(parsed_line)
                key = str(parsed_req)
                if key not in found:
                    found.add(key)
                    result.append(parsed_req)
            else:
                self._merge_option_line(opt, parsed_line.opts, parsed_line.filename)
        for req in result:
            if req.from_file != str(self.path):
                continue
            for illegal_option in self._illegal_options:
                if req.options.get(illegal_option):
                    msg = (
                        f"Cannot use --{illegal_option} in deps list,"
                        "it must be in requirements file. ({req})"
                    )
                    raise ValueError(msg)
        return result


class Resource:
    def __init__(self, input_obj: str, output_obj: str = "") -> None:
        self._input_obj = input_obj
        self._output_obj = output_obj

    def write(self, dest_folder: str) -> None:
        full_dest_folder = os.path.join(dest_folder, self._output_obj)
        os.makedirs(os.path.dirname(full_dest_folder), exist_ok=True)
        with (
            open(self._input_obj) as input_file,
            open(full_dest_folder, mode="w") as output_file,
        ):
            output_file.write(input_file.read())


class Tool:
    def __init__(
        self,
        tool_name: str,
        version_spec: str = "",
        additionals: list[str] = [],
        resources: list[Resource] = [],
    ):
        self._tool_name = tool_name
        self._version_spec = version_spec
        self._additionals = additionals
        self._resources = resources

    @property
    def name(self) -> str:
        return self._tool_name

    @property
    def with_version(self) -> str:
        return f"{self._tool_name}{self._version_spec}"

    @property
    def additionals(self) -> list[str]:
        return self._additionals

    @property
    def resources(self) -> list[Resource]:
        return self._resources


class AuthManager:
    def __init__(self, auth_mode: Literal["ssh", "token"]) -> None:
        self._token = None
        self._ssh_key_path = None
        if auth_mode == "ssh":
            self._ssh_key_path = input("chemin vers la clé public: ")
        self._token = os.environ.get("GITHUB_TOKEN") or getpass.getpass(
            "Personnal Access Token: ",
        )
        self._auth_mode = auth_mode

    @property
    def auth_mode(self) -> Literal["ssh", "token"]:
        return self._auth_mode

    @property
    def ssh_key_path(self) -> str | None:
        return self._ssh_key_path

    @property
    def token(self) -> str | None:
        return self._token


EXTERNAL_TOOLS = {
    tool.name: tool
    for tool in (
        Tool(
            "pgadmin4",
            resources=[
                Resource(
                    os.path.join(
                        os.path.dirname(__file__),
                        "resources",
                        "postgres-docker-compose.yml",
                    ),
                    output_obj=os.path.join(
                        "docker-compose",
                        "docker-compose.yml",
                    ),
                ),
            ],
        ),
        Tool(
            "localstack",
            additionals=["awscli-local"],
        ),
    )
}


def is_git_repo(repo_name: str) -> bool:
    try:
        git.Repo(repo_name).git_dir
        return True
    except git.InvalidGitRepositoryError:
        return False


def setup_venv(dest_path: str, force: bool = False) -> None:
    venv_path = os.path.join(dest_path, ".venv")
    if not os.path.exists(venv_path) or force:
        click.echo(f"Création du virtualenv {venv_path}")
        virtualenv.cli_run([venv_path])
    if os.path.exists(os.path.join(dest_path, "tox.ini")):
        try:
            tox_args = ["devenv", "-e", "devenv", "-c", dest_path, venv_path]
            if force:
                tox_args.append("-r")
            click.echo("Installation des dépendances")
            with mock.patch(
                "tox.tox_env.python.pip.req_file.PythonDeps",
                NonSortedPythonDeps,
            ):
                tox.run.run(tox_args)
        except SystemExit as e:
            if e.args != (0,):
                click.echo(
                    f"Tox ne peut initialiser l'environnement de dev pour {dest_path}",
                )

    if os.path.exists(
        config_file := os.path.realpath(
            os.path.join(
                dest_path,
                ".pre-commit-config.yaml",
            ),
        ),
    ):
        click.echo("Installation de pre-commit")
        from pre_commit.commands.install_uninstall import install
        from pre_commit.commands.install_uninstall import Store

        install(
            config_file,
            Store(),
            None,
            overwrite=force,
            hooks=True,
            git_dir=os.path.realpath(os.path.join(dest_path, ".git")),
        )


def callback_external_tool(ctx: click.Context, param: Any, value: Any) -> Tool:
    return EXTERNAL_TOOLS[value]


def find_exec_path() -> str:
    system = platform.system()
    if system == "Windows":
        return "Scripts"
    return "bin"


def create_tool_folder(
    tool: Tool,
    dest_path_folder: str = ".",
    force: bool = False,
) -> None:
    dest_path = os.path.join(dest_path_folder, tool.name)
    if os.path.exists(dest_path) and not force:
        click.echo(
            f"Le dossier {dest_path} existe déjà, l'installation de l'outil est skip",
        )
        return
    if os.path.exists(dest_path) and force:
        click.echo(f"Suppression du dossier {dest_path}")
        shutil.rmtree(dest_path)
    click.echo(f"Création du dossier {dest_path}")
    os.makedirs(dest_path, exist_ok=True)
    venv_path = os.path.join(dest_path, ".venv")
    virtualenv.cli_run([venv_path])
    subprocess.call(
        [
            os.path.join(venv_path, find_exec_path(), "pip"),
            "install",
            tool.with_version,
            *tool.additionals,
        ],
    )
    for resource in tool.resources:
        resource.write(dest_path)


def clone_repo(
    repo: Any,
    auth_manager: AuthManager,
    dest_path_folder: str = ".",
    force: bool = False,
) -> str:
    dest_path = os.path.join(dest_path_folder, repo.name)
    if os.path.exists(dest_path) and not force:
        click.echo(
            f"Le dossier {dest_path} existe déjà, le clonage du repo est ignorée",
        )
        return dest_path
    if os.path.exists(dest_path) and force:
        click.echo(f"Suppression du dossier {dest_path}")
        shutil.rmtree(dest_path)
    click.echo(f"Clone du répertoire {repo.name}")
    if auth_manager.auth_mode == "ssh":
        repo = git.Repo.clone_from(
            repo.clone_url,
            dest_path,
            env={
                "GIT_SSH_COMMAND": f"ssh -i {auth_manager.ssh_key_path}",
            },
        )
    else:
        repo = git.Repo.clone_from(
            repo.clone_url,
            dest_path,
        )
    return dest_path


def assert_argument(args: list[Any], all_target: bool) -> None:
    if args and all_target:
        raise click.UsageError(
            "L'options '--all' ne peut être utilisé avec un liste d'argument fournie",
        )
    if not args and not all_target:
        raise click.UsageError(
            "Si l'option '--all' n'est pas utilisé, au moin un argument doit être fournie",
        )


class GenericOptions:
    def __init__(self, all_target: bool, target: str, force: bool) -> None:
        self.all_target = all_target
        self.dest_path_folder = target
        self.force = force

        if not os.path.exists(self.dest_path_folder):
            os.makedirs(self.dest_path_folder)


@click.group()
@click.option(
    "-t",
    "--target",
    type=click.Path(exists=False, dir_okay=True, file_okay=False),
    default=".",
    show_default=True,
    help="Répertoire cible",
)
@click.option(
    "-a/-A",
    "--all/--not-all",
    "all_target",
    is_flag=True,
    show_default=True,
    default=False,
    help="Effectue l'opération pour l'ensemble des cibles de la commande fournie",
)
@click.option(
    "-f/-F",
    "--force/--no-force",
    is_flag=True,
    show_default=True,
    default=False,
)
@click.pass_context
def cli(ctx: click.Context, target: str, all_target: bool, force: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["OPTIONS"] = GenericOptions(all_target, target, force)


@cli.group(name="repo")
@click.pass_context
def repo_manager(ctx: click.Context) -> None:
    ...


@repo_manager.command(
    name="venv",
    short_help="(Re-)Génère les virtualenv de dev'",
)
@click.argument("folders", nargs=-1)
@click.pass_context
def generate_venv(
    ctx: click.Context,
    folders: list[str],
) -> None:
    options: GenericOptions = ctx.obj["OPTIONS"]
    assert_argument(folders, options.all_target)

    if options.all_target:
        dirs = os.listdir(options.dest_path_folder)
    else:
        dirs = folders
    for folder in map(lambda x: os.path.join(options.dest_path_folder, x), dirs):
        if not os.path.exists(folder):
            click.echo(
                "Impossible de générer l'environnement de dev',"
                f"le dossier {folder} n'existe pas",
            )
            continue
        if os.path.isfile(folder):
            continue
        setup_venv(folder, force=options.force)


@repo_manager.command(
    name="checkout",
    short_help="checkout l'ensemble des repos locaux git sur la branche spécifié",
)
@click.argument("folders", nargs=-1)
@click.option(
    "-b",
    "--branch",
    default="develop",
    show_default=True,
    help="nom de la branche",
)
@click.pass_context
def checkout_branch(
    ctx: click.Context,
    folders: list[str],
    branch: str,
) -> None:
    options: GenericOptions = ctx.obj["OPTIONS"]
    assert_argument(folders, options.all_target)
    if options.all_target:
        dirs = os.listdir(options.dest_path_folder)
    else:
        dirs = folders
    for repo_name in map(lambda x: os.path.join(options.dest_path_folder, x), dirs):
        if not os.path.exists(repo_name):
            click.echo(
                f"Impossible de checkout la branche '{branch}',"
                f"le dossier {repo_name} n'existe pas",
            )
            continue
        if not is_git_repo(repo_name):
            continue
        repo = git.Repo(repo_name)
        pulling = True
        if repo.active_branch.name != branch:
            click.echo(f"Checkout {branch} pour {repo_name}")
            try:
                repo.git.checkout(branch)
            except git.GitCommandError:
                pulling = False
                try:
                    repo.git.checkout(branch, b=True)
                except Exception as e:
                    click.echo(
                        f"Impossible de checkout la branche {branch} du repo {repo_name} {e}",
                    )
        if pulling and repo.git is not None and repo.active_branch in repo.references:
            click.echo(f"Pull {branch} pour {repo_name}")
            try:
                repo.git.pull()
            except Exception:
                click.echo(f"Impossible de pull la branche {repo.active_branch}")


@repo_manager.command(
    short_help=("Clone un repo github de l'organisation founi en paramètre"),
)
@click.argument("repos", nargs=-1)
@click.option(
    "-v/-V",
    "--with-venv/--without-venv",
    is_flag=True,
    show_default=True,
    default=False,
)
@click.option(
    "-b",
    "--branch",
    default="develop",
    show_default=True,
    help="nom de la branche par défaut",
)
@click.option(
    "-o",
    "-u",
    "--organization",
    "--user",
    "organization_or_user",
    show_default=True,
    help=("Nom de l'organisation ou l'utilisateur" "proprietaire du repo"),
)
@click.option(
    "-p",
    "--prefix",
    default="",
    show_default=True,
    help=("prefix utilisé pour filtré la liste des repos récupéré"),
)
@click.option(
    "-m",
    "--auth-mode",
    type=click.Choice(["ssh", "token"]),
    default="token",
    show_default=True,
    help="méthode utilisé pour l'authentification git",
)
@click.pass_context
def clone(
    ctx: click.Context,
    repos: list[str],
    with_venv: bool,
    branch: str,
    organization_or_user: str,
    prefix: str,
    auth_mode: Literal["ssh", "token"],
) -> None:
    options: GenericOptions = ctx.obj["OPTIONS"]

    assert_argument(repos, options.all_target)

    auth_manager = AuthManager(auth_mode)
    gh_manager = github.Github(login_or_token=auth_manager.token)

    results: Any
    if options.all_target:
        results = gh_manager.search_repositories(
            prefix,
            **{
                "in": "name",
                "org": organization_or_user,
                "user": organization_or_user,
            },
        )
    else:
        try:
            results = [
                gh_manager.get_repo(f"{organization_or_user}/{repo}") for repo in repos
            ]
        except github.UnknownObjectException:
            raise click.UsageError(
                "un ou plusieur repository n'existe pas "
                "ou ne sont pas associé "
                f"a l'organisation ou l'utilisateur {organization_or_user}",
            )
    click.echo("Clone des repos")
    for repo in results:
        if repo.name.startswith(prefix) and (
            repo.name
            != os.path.basename(__file__).removesuffix(".py").replace("_", "-")
        ):
            try:
                clone_repo(
                    repo,
                    auth_manager=auth_manager,
                    dest_path_folder=options.dest_path_folder,
                    force=options.force,
                )
            except Exception as e:
                click.echo(f"Le clone ne s'est pas bien terminé {e}")

    if with_venv:
        ctx.invoke(generate_venv, folders=repos)

    ctx.invoke(checkout_branch, folders=repos, branch=branch)

    click.echo("L'environement a été monter avec succès.")


@cli.group(name="tool")
@click.pass_context
def tool_manager(ctx: click.Context) -> None:
    ...


@tool_manager.command(
    name="install",
    short_help=(
        "Installe l'outil du référentiel commun demandé "
        f"({', '.join(EXTERNAL_TOOLS)})"
    ),
)
@click.argument("tools", nargs=-1)
@click.pass_context
def install_tool(ctx: click.Context, tools: list[str]) -> None:
    options: GenericOptions = ctx.obj["OPTIONS"]
    assert_argument(tools, options.all_target)

    target_tools: Iterable[Tool]
    if options.all_target:
        target_tools = EXTERNAL_TOOLS.values()
    else:
        target_tools = [EXTERNAL_TOOLS[tool] for tool in tools]
    for tool in target_tools:
        create_tool_folder(
            tool,
            dest_path_folder=options.dest_path_folder,
            force=options.force,
        )
    click.echo("L'environement a été monter avec succès.")


BODY = {
    "required_linear_history": False,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "block_creations": False,
    "required_conversation_resolution": True,
    "lock_branch": False,
    "allow_fork_syncing": False,
    "enforce_admins": True,
    "required_status_checks": {
        "strict": True,
        "contexts": ["code-quality / code-quality"],
    },
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": False,
        "require_last_push_approval": True,
        "required_approving_review_count": 1,
    },
    "restrictions": None,
}


async def create_branch_restriction(
    repo: github.Repository.Repository,
    branch: str,
    token: str,
) -> None:
    click.echo(f"set branch {branch} restrictions to {repo.name}")
    result = requests.put(
        f"https://api.github.com/repos/{repo.owner.login}/"
        f"{repo.name}/branches/{branch}/protection",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json=BODY,
        timeout=10,
    )
    click.echo(
        f"({branch=}|{repo.name=})[{result.status_code}] {result.text}",
    )


@cli.command(name="protect-branch", hidden=True)
@click.option("-u", "--user-or-org")
@click.option("-p", "--prefix", default="")
@click.option("-r", "--repo-name", default=None)
def set_branch_protection_rule(
    user_or_org: str,
    prefix: str,
    repo_name: str | None,
) -> None:
    token = os.environ["GITHUB_TOKEN"]
    githubapi = github.Github(login_or_token=token)
    branches = ("main", "release", "develop")
    repos: Iterable[github.Repository.Repository]
    if not repo_name:
        repos = githubapi.search_repositories(
            prefix,
            **{
                "in": "name",
                "org": user_or_org,
                "user": user_or_org,
            },
        )
    else:
        repos = [githubapi.get_repo(f"{user_or_org}/{repo_name}")]
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        asyncio.gather(
            *(
                create_branch_restriction(repo, branch, token)
                for repo, branch in it.product(repos, branches)
            ),
        ),
    )
