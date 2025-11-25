from typing import List, Dict, Any
from evillimiter.console.io import IO

class BarChart:
    def __init__(self, draw_char: str = '▇', max_bar_length: int = 30):
        self.draw_char = draw_char
        self.max_bar_length = max_bar_length
        self._data: List[Dict[str, Any]] = []

    def add_value(self, value: float, prefix: str, suffix: str = '') -> None:
        self._data.append({'value': value, 'prefix': prefix, 'suffix': suffix})

    def get(self, reverse: bool = False) -> str:
        if not self._data:
            return ""

        def remap(n, old_max, new_max):
            if old_max == 0: return 0
            return (n * new_max) / old_max
        
        # Sort data
        sorted_data = sorted(self._data, key=lambda x: x['value'], reverse=reverse)

        # Determine scaling factor
        # If reverse=True (descending), max is at index 0. Else at index -1
        max_val = sorted_data[0]['value'] if reverse else sorted_data[-1]['value']
        
        # Calculate padding for alignment
        max_prefix_len = max((len(x['prefix']) for x in sorted_data), default=0) + 1

        chart_lines = []
        for item in sorted_data:
            val = item['value']
            bar_len = round(remap(val, max_val, self.max_bar_length))
            
            # Formatting
            prefix_padded = f"{item['prefix']}{' ' * (max_prefix_len - len(item['prefix']))}"
            bar = self.draw_char * bar_len
            
            chart_lines.append(f"{prefix_padded}: {bar} {item['suffix']}")

        return "\n".join(chart_lines)