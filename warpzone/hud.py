"""WarpZone screen layer: a Mario-style HUD with a plain-text fallback.

Worlds:
  1-1 WARP PIPES      JS discovery (gau / waymore / katana / hakrawler / spider)
  1-2 COIN HEAVEN     fetch + prettify + endpoint mining (coins!)
  1-3 SECRET VAULTS   secrets and exposed source maps
  1-4 BOWSER'S CASTLE DOM-XSS leads, reflection probing, browser confirm
  1-5 REPORT CASTLE   write the report (md / json / html)

If rich is not installed, everything falls back to plain prints.
"""
import random
import time

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.text import Text
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

CREATOR = "Shaimaa Khattab"

# Dusty palette: muted, vintage, easy on the eyes. Rose, mauve, plum,
# warm sand, sage. No neon.
PINK = "#c98a95"      # dusty rose (headlines, borders)
MAGENTA = "#bb8f9d"   # dusty mauve (soft accent, sfx)
LAVENDER = "#9d8aa6"  # dusty plum (purple accent)
ROSE = "#d2b9a3"      # warm sand (light text)
MINT = "#a3b18a"      # dusty sage (good notes)

BANNER = r"""
██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗███████╗
██║    ██║██╔══██╗██╔══██╗██╔══██╗╚══███╔╝██╔═══██╗████╗  ██║██╔════╝
██║ █╗ ██║███████║██████╔╝██████╔╝  ███╔╝ ██║   ██║██╔██╗ ██║█████╗
██║███╗██║██╔══██║██╔══██╗██╔═══╝  ███╔╝  ██║   ██║██║╚██╗██║██╔══╝
╚███╔███╔╝██║  ██║██║  ██║██║     ███████╗╚██████╔╝██║ ╚████║███████╗
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
"""

PLAIN_BANNER = r"""
=====================================================
   W A R P Z O N E   -   JS recon and XSS arsenal
          every JS file is a warp pipe
=====================================================
"""

LEVELS = {
    1: ("WARP PIPES", "collecting JS files from every green pipe"),
    2: ("COIN HEAVEN", "prettifying and mining endpoints (coins!)"),
    3: ("SECRET VAULTS", "secrets and exposed source maps"),
    4: ("BOWSER'S CASTLE", "DOM-XSS leads, reflection probe, browser confirm"),
    5: ("REPORT CASTLE", "writing the report"),
}

SFX = ["1-UP!", "COIN GET!", "POWER-UP!", "STAR POWER!", "PIPE WARP!",
       "FIREBALL!", "LET'S-A-GO!"]
ENEMIES = ["A Goomba sat on the response, jumped right over it.",
           "A Koopa blocked the request, shell-kicked it, moving on.",
           "Bowser threw a fireball on the wire, dodged it."]


def _sfx():
    return random.choice(SFX)


class HUD:
    """Shows the run as a little game. game=False (or no rich) gives plain text."""

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
        """Wrap caller text so brackets inside findings stay literal."""
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
        made = f"Made by {CREATOR}. Every JS file is a warp pipe."
        warn = "AUTHORIZED TARGETS ONLY. Scope is checked on every request."
        if self.game_on:
            self._print(f"[bold {PINK}]{BANNER}[/]")
            self._print(f"[bold {LAVENDER}]        {made}[/]")
            self._print(f"[bold {PINK}]        {warn}[/]")
        else:
            self._print(PLAIN_BANNER)
            self._print("        " + made)
            self._print("        " + warn)
        self._print()

    def level(self, world):
        name, tag = LEVELS.get(world, ("???", ""))
        self.score += 100
        if self.game_on:
            panel = Panel(
                f"[bold white]{tag}[/]",
                title=f"[bold {MAGENTA}]WORLD 1-{world}  {name}[/]",
                border_style=PINK, box=box.DOUBLE, padding=(0, 2))
            self._print(panel)
        else:
            print(f"\n=== WORLD 1-{world}: {name} - {tag} ===", flush=True)

    def course_clear(self, world, extra=""):
        name, _ = LEVELS.get(world, ("???", ""))
        mins, secs = divmod(int(time.time() - self.t0), 60)
        if self.game_on:
            body = (f"SCORE {self.score:07d}    COINS {self.coins:05d}    "
                    f"LIVES x{self.lives}    TIME {mins:02d}:{secs:02d}\n")
            if extra:
                body += f"[dim]{extra}[/]\n"
            self._print(Panel(body, title=f"[bold {MAGENTA}]COURSE CLEAR[/]",
                              subtitle=f"[{LAVENDER}]WORLD 1-{world}  {name}[/]",
                              border_style=MAGENTA, box=box.HEAVY, padding=(0, 2)))
        else:
            extra_s = f" | {extra}" if extra else ""
            print(f"*** COURSE CLEAR - WORLD 1-{world} {name} | "
                  f"SCORE {self.score:07d}  COINS {self.coins:05d}  LIVES x{self.lives}"
                  f"{extra_s} ***", flush=True)

    def game_over(self, msg):
        if self.game_on:
            self._print(Panel(f"[bold {PINK}]{msg}[/]",
                              title=f"[bold {PINK}]GAME OVER (bug hunters respawn)[/]",
                              border_style=PINK, box=box.HEAVY))
        else:
            print(f"!!! GAME OVER - {msg}", flush=True)

    # ------------------------------------------------------------ events --
    def sfx(self, msg=""):
        self._print(self._t(f"{_sfx()} {msg}", MAGENTA))

    def coin(self, n=1):
        self.coins += n
        self.score += 200 * n
        if self.coins % 100 < n:      # every 100 coins, a 1-UP
            self.lives += 1
            self.sfx("100 coins, 1-UP! LIVES x" + str(self.lives))

    def secret_found(self, kind, conf):
        self.score += 1000 if conf == "high" else 300

    def sourcemap_found(self):
        self.map_count += 1
        self.score += 2500
        self.sfx("exposed source map, 2500 pts (near-original source!)")

    def star(self):
        self.stars += 1
        self.score += 1500

    def pipe(self, msg):
        self._print(self._t(f">> entering pipe: {msg}", LAVENDER))

    def enemy(self, msg=""):
        self._print(self._t(f"[enemy] {msg or random.choice(ENEMIES)}", ROSE))

    def note(self, msg):
        self._print(self._t(f"  . {msg}", "dim"))

    def warn(self, msg):
        self._print(self._t(f"[!] {msg}", f"bold {PINK}"))

    def error(self, msg):
        self._print(self._t(f"[x] {msg}", f"bold {PINK}"))

    def item(self, msg):
        self._print(self._t(f"  -> {msg}", MINT))

    # ----------------------------------------------------------- recon ----
    def recon_summary(self, data, outdir):
        """A clean, readable map of what recon found."""
        rows = [
            ("Subdomains (in scope)", len(data["subdomains"]), "subdomains.txt"),
            ("Live hosts", len(data["live"]), "live_hosts.txt"),
            ("URLs", len(data["urls"]), "urls.txt"),
            ("Live JS files", len(data["js_files"]), "js_files.txt"),
            ("Endpoints from JS", len(data["js_endpoints"]), "js_endpoints.txt"),
            ("URLs with params", len(data["params"]), "params.txt"),
            ("Interesting paths", len(data["interesting"]), "interesting.txt"),
        ]
        if self.game_on:
            from rich.table import Table
            t = Table(box=box.SIMPLE_HEAVY, border_style=LAVENDER,
                      title=f"[bold {PINK}]RECON MAP[/]  [dim]{data['target']}[/]",
                      title_justify="left", pad_edge=False)
            t.add_column("found", style=ROSE, no_wrap=True)
            t.add_column("count", style=f"bold {MAGENTA}", justify="right")
            t.add_column("file", style=MINT)
            for label, n, fname in rows:
                t.add_row(label, str(n), fname)
            self._print(t)
            self._print(f"[dim]scope:[/] [{LAVENDER}]{data['scope_desc']}[/]")
            self._print(f"[dim]files in[/] [{MINT}]{outdir}[/]")
            if data["interesting"]:
                self._print(f"[bold {PINK}]look here first:[/]")
                for u in data["interesting"][:8]:
                    self._print(self._t("  -> " + u, MINT))
        else:
            print("\n==================== RECON MAP:", data["target"], "====================")
            for label, n, fname in rows:
                print(f"  {label:<24} {n:>6}   {fname}")
            print("  scope:", data["scope_desc"])
            print("  files in:", outdir)
            if data["interesting"]:
                print("  look here first:")
                for u in data["interesting"][:8]:
                    print("    ->", u)
        self._print()

    # ------------------------------------------------------------- hud ----
    def hud(self, extra=""):
        mins, secs = divmod(int(time.time() - self.t0), 60)
        line = (f"WORLD 1-x   SCORE {self.score:07d}   COINS {self.coins:05d}   "
                f"1-UPS {self.map_count}   STARS {self.stars}   LIVES x{self.lives}   "
                f"TIME {mins:02d}:{secs:02d}")
        if self.game_on:
            self._print(Rule(f"[bold {MAGENTA}]{line}[/]" + (f"  [dim]{extra}[/]" if extra else ""),
                             style=PINK))
        else:
            print(f"--- {line} {extra} ---", flush=True)
