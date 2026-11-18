"""WarpZone game layer: Mario-style Rich HUD with a plain-terminal fallback.

Worlds:
  1-1 WARP PIPES      — JS discovery (gau / waymore / katana / hakrawler / spider)
  1-2 COIN HEAVEN     — fetch + prettify + endpoint mining (coins!)
  1-3 SECRET VAULTS   — secrets & exposed source maps
  1-4 BOWSER'S CASTLE — DOM-XSS taint leads + the XSS arena
  1-5 REPORT CASTLE   — write the war-room report (md / json / html)

Everything degrades to plain prints if `rich` is not installed.
"""
import random
import time

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

CREATOR = "Shaimaa Khattab"

BANNER = r"""
██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗███████╗
██║    ██║██╔══██╗██╔══██╗██╔══██╗╚══███╔╝██╔═══██╗████╗  ██║██╔════╝
██║ █╗ ██║███████║██████╔╝██████╔╝  ███╔╝ ██║   ██║██╔██╗ ██║█████╗
██║███╗██║██╔══██║██╔═══╝ ██╔═══╝  ███╔╝  ██║   ██║██║╚██╗██║██╔══╝
╚███╔███╔╝██║  ██║██║     ██║     ███████╗╚██████╔╝██║ ╚████║███████╗
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
"""

PLAIN_BANNER = r"""
=====================================================
   W A R P Z O N E  —  JS recon & XSS arsenal
        every JS file is a warp pipe  🍄
=====================================================
"""

LEVELS = {
    1: ("WARP PIPES", "collecting JS files from every green pipe"),
    2: ("COIN HEAVEN", "prettifying + mining endpoints (coins!)"),
    3: ("SECRET VAULTS", "secrets & exposed source maps"),
    4: ("BOWSER'S CASTLE", "DOM-XSS taint leads + XSS arena"),
    5: ("REPORT CASTLE", "writing the war-room report"),
}

SFX = ["♪ 1-UP!", "♪ COIN GET!", "✦ POWER-UP!", "★ STAR POWER!", "♪ PIPE WARP!",
       "✦ FIREBALL!", "★ COURSE SPARKLE!"]
ENEMIES = ["A Goomba stole the response — jumping over it!",
           "A Koopa blocked the request — shell kicked, moving on!",
           "Bowser set a fireball on the wire — dodged!"]


def _sfx():
    return random.choice(SFX)


class HUD:
    """Presentational game layer. `game=False` (or no rich) -> plain output."""

    def __init__(self, game=True):
        self.game_on = bool(game) and HAVE_RICH
        self.rich = HAVE_RICH
        self.score = 0
        self.coins = 0
        self.lives = 3
        self.map_count = 0
        self.stars = 0
        self.t0 = time.time()

    # ------------------------------------------------------ primitives ----
    def _t(self, s, style):
        """Wrap caller data in rich Text so brackets in findings stay literal."""
        if self.rich:
            return Text(str(s), style=style)
        return str(s)

    def _print(self, *args, **kw):
        if self.game_on:
            Console().print(*args, **kw)
        else:
            print(" ".join(str(a) for a in args), flush=True)

    # ---------------------------------------------------------- screens ---
    def banner(self):
        self._print(f"[bold green]{BANNER}[/bold green]" if self.game_on else PLAIN_BANNER)
        self._print(f"[bold yellow]        🍄 Created by {CREATOR} — every JS file is a warp pipe[/bold yellow]")
        self._print("[bold red]        ⚠  AUTHORIZED TARGETS ONLY — scope is enforced on every request[/bold red]")
        self._print()

    def level(self, world):
        name, tag = LEVELS.get(world, ("???", ""))
        self.score += 100  # entering a world is itself progress
        if self.game_on:
            panel = Panel(
                f"[bold white]{tag}[/bold white]",
                title=f"[bold yellow]WORLD 1-{world} — {name}[/bold yellow]",
                border_style="green", box=box.DOUBLE, padding=(0, 2))
            self._print(panel)
        else:
            print(f"\n=== WORLD 1-{world}: {name} — {tag} ===", flush=True)

    def course_clear(self, world, extra=""):
        name, _ = LEVELS.get(world, ("???", ""))
        mins, secs = divmod(int(time.time() - self.t0), 60)
        if self.game_on:
            body = (f"SCORE {self.score:07d}    COINS {self.coins:05d}    "
                    f"LIVES x{self.lives}    TIME {mins:02d}:{secs:02d}\n")
            if extra:
                body += f"[dim]{extra}[/dim]\n"
            self._print(Panel(body, title="[bold green]★ ★ ★  COURSE CLEAR  ★ ★ ★[/bold green]",
                              subtitle=f"[yellow]WORLD 1-{world} — {name}[/yellow]",
                              border_style="yellow", box=box.HEAVY, padding=(0, 2)))
        else:
            extra_s = f" | {extra}" if extra else ""
            print(f"*** COURSE CLEAR — WORLD 1-{world} {name} | "
                  f"SCORE {self.score:07d}  COINS {self.coins:05d}  LIVES x{self.lives}"
                  f"{extra_s} ***", flush=True)

    def game_over(self, msg):
        if self.game_on:
            self._print(Panel(f"[bold red]{msg}[/bold red]",
                              title="[bold red]GAME OVER (but bug hunters respawn)[/bold red]",
                              border_style="red", box=box.HEAVY))
        else:
            print(f"!!! GAME OVER — {msg}", flush=True)

    # ------------------------------------------------------------ events --
    def sfx(self, msg=""):
        self._print(self._t(f"{_sfx()} {msg}", "magenta"))

    def coin(self, n=1):
        self.coins += n
        self.score += 200 * n
        if self.coins % 100 < n:      # every 100 coins -> 1-UP
            self.lives += 1
            self.sfx("100 COINS → 1-UP! LIVES x" + str(self.lives))

    def secret_found(self, kind, conf):
        self.score += 1000 if conf == "high" else 300

    def sourcemap_found(self):
        self.map_count += 1
        self.score += 2500
        self.sfx("EXPOSED SOURCE MAP — 2500 PTS (near-original source!)")

    def star(self):
        self.stars += 1
        self.score += 1500

    def pipe(self, msg):
        self._print(self._t(f"▄▄▄█▀▀▄  entering pipe: {msg}", "cyan"))

    def enemy(self, msg=""):
        self._print(self._t(f"👾 {msg or random.choice(ENEMIES)}", "yellow"))

    def note(self, msg):
        self._print(self._t(f"· {msg}", "dim"))

    def warn(self, msg):
        self._print(self._t(f"⚠ {msg}", "bold yellow"))

    def error(self, msg):
        self._print(self._t(f"✖ {msg}", "bold red"))

    def item(self, msg):
        self._print(self._t(f"  ➜ {msg}", "green"))

    # ------------------------------------------------------------- hud ----
    def hud(self, extra=""):
        mins, secs = divmod(int(time.time() - self.t0), 60)
        line = (f"WORLD ★ 1-x   SCORE {self.score:07d}   COINS {self.coins:05d}   "
                f"1-UPS {self.map_count}   STARS {self.stars}   LIVES x{self.lives}   "
                f"TIME {mins:02d}:{secs:02d}")
        if self.game_on:
            self._print(Rule(f"[bold yellow]{line}[/bold yellow]" + (f"  [dim]{extra}[/dim]" if extra else ""),
                             style="green"))
        else:
            print(f"--- {line} {extra} ---", flush=True)
