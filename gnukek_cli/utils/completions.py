from click import Context, Parameter, ParamType
from click.shell_completion import CompletionItem
from dependency_injector.wiring import Provide, inject

from gnukek_cli.config import SettingsProvider
from gnukek_cli.container import Container


class KeyIdParam(ParamType):
    name = "key_id"

    @inject
    def shell_complete(
        self,
        ctx: Context,
        param: Parameter,
        incomplete: str,
        *,
        settings_provider: SettingsProvider = Provide[Container.settings_provider]
    ) -> list[CompletionItem]:
        try:
            settings = settings_provider.get_settings()
            all_keys = {*settings.private, *settings.public}
            return [
                CompletionItem(key_id)
                for key_id in all_keys
                if key_id.startswith(incomplete)
            ]
        except Exception:
            return []
