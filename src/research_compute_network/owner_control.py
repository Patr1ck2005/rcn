"""Machine-owner policy controls and optional Windows tray UI."""

from __future__ import annotations

from .models import MachineMode
from .repository import MetadataRepository
from .service import NetworkService


def set_owner_mode(
    repository: MetadataRepository,
    *,
    machine_id: str,
    owner_user_id: str,
    mode: MachineMode,
) -> None:
    policy = repository.get_policy(machine_id)
    if policy is None:
        raise KeyError(f"machine policy not found: {machine_id}")
    if policy.owner_user_id != owner_user_id:
        raise PermissionError("owner ID does not match the machine policy")
    policy.owner_mode = mode
    NetworkService(repository).update_policy(policy, actor_id=owner_user_id)


def run_tray(database_url: str, *, machine_id: str, owner_user_id: str) -> None:
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError as exc:
        raise RuntimeError("install the 'owner-ui' extra to use the tray controller") from exc

    repository = MetadataRepository(database_url)
    repository.init_schema()
    image = Image.new("RGB", (64, 64), "#0f172a")
    draw = ImageDraw.Draw(image)
    draw.ellipse((12, 12, 52, 52), fill="#38bdf8")
    draw.rectangle((29, 19, 35, 45), fill="#0f172a")

    def action(mode: MachineMode):
        def callback(icon, item) -> None:
            set_owner_mode(
                repository,
                machine_id=machine_id,
                owner_user_id=owner_user_id,
                mode=mode,
            )
            icon.notify(f"Machine sharing mode: {mode.value}", "Research Compute Network")
        return callback

    icon = pystray.Icon(
        "research-compute-network",
        image,
        "Research Compute Network",
        menu=pystray.Menu(
            pystray.MenuItem("Open", action(MachineMode.OPEN)),
            pystray.MenuItem("Drain", action(MachineMode.DRAIN)),
            pystray.MenuItem("Pause", action(MachineMode.PAUSED)),
            pystray.MenuItem("Emergency stop", action(MachineMode.EMERGENCY_STOP)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit tray", lambda icon, item: icon.stop()),
        ),
    )
    icon.run()
