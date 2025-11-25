import re
import colorama
from typing import Optional

from . import shell

class IO:
    # Sử dụng raw string cho regex để tránh DeprecationWarning
    _ANSI_CSI_RE = re.compile(r'\001?\033\[((?:\d|;)*)([a-zA-Z])\002?') 

    Back = colorama.Back
    Fore = colorama.Fore
    Style = colorama.Style

    colorless: bool = False

    @staticmethod
    def initialize(colorless: bool = False) -> None:
        """Initializes console input and output."""
        IO.colorless = colorless
        if not colorless:
            colorama.init(autoreset=True)

    @staticmethod
    def print(text: str, end: str = '\n', flush: bool = False) -> None:
        if IO.colorless:
            text = IO._remove_colors(text)
        print(text, end=end, flush=flush)

    @staticmethod
    def ok(text: str, end: str = '\n') -> None:
        IO.print(f'{IO.Style.BRIGHT}{IO.Fore.LIGHTGREEN_EX}OK{IO.Style.RESET_ALL}   {text}', end=end)

    @staticmethod
    def error(text: str) -> None:
        IO.print(f'{IO.Style.BRIGHT}{IO.Fore.LIGHTRED_EX}ERR{IO.Style.RESET_ALL}  {text}')

    @staticmethod
    def spacer() -> None:
        IO.print('')

    @staticmethod
    def input(prompt: str) -> str:
        if IO.colorless:
            prompt = IO._remove_colors(prompt)
        return input(prompt)

    @staticmethod
    def clear() -> None:
        shell.execute('clear', root=False)

    @staticmethod
    def _remove_colors(text: str) -> str:
        return IO._ANSI_CSI_RE.sub('', text)