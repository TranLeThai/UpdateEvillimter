import enum
import logging
from typing import List, Optional, Any, Callable, NamedTuple
from dataclasses import dataclass, field

from evillimiter.console.io import IO

# Thiết lập logger
logger = logging.getLogger(__name__)

class CommandType(enum.Enum):
    PARAMETER = 1
    FLAG = 2
    PARAMETERIZED_FLAG = 3

@dataclass
class CommandDefinition:
    type: CommandType
    name: str
    identifier: Optional[str] = None

@dataclass
class SubparserDefinition:
    identifier: str
    subparser: 'CommandParser'
    handler: Optional[Callable[[Any], None]]

class CommandParser:
    def __init__(self):
        self._commands: List[CommandDefinition] = []
        self._subparsers: List[SubparserDefinition] = []

    def add_parameter(self, name: str) -> None:
        """Thêm tham số vị trí (bắt buộc). Ví dụ: limit <ID>"""
        self._commands.append(CommandDefinition(CommandType.PARAMETER, name))

    def add_flag(self, identifier: str, name: str) -> None:
        """Thêm cờ tùy chọn (boolean). Ví dụ: --force"""
        self._commands.append(CommandDefinition(CommandType.FLAG, name, identifier))

    def add_parameterized_flag(self, identifier: str, name: str) -> None:
        """Thêm cờ có tham số đi kèm. Ví dụ: --rate 100kbit"""
        self._commands.append(CommandDefinition(CommandType.PARAMETERIZED_FLAG, name, identifier))

    def add_subparser(self, identifier: str, handler: Optional[Callable] = None) -> 'CommandParser':
        """Tạo subparser cho lệnh con. Ví dụ: 'scan' trong 'evillimiter scan'"""
        subparser = CommandParser()
        self._subparsers.append(SubparserDefinition(identifier, subparser, handler))
        return subparser

    def parse(self, args: List[str]) -> Optional[Any]:
        """Phân tích danh sách đối số đầu vào."""
        # Tạo dictionary chứa kết quả với giá trị mặc định None
        result_dict = {cmd.name: None for cmd in self._commands}
        
        # Nếu danh sách args rỗng và không có lệnh nào, return object rỗng
        if not args and not self._commands and not self._subparsers:
            return type('ParseResult', (object,), {})()

        skip_next = False
        
        # 1. Xử lý Subparser trước (nếu là argument đầu tiên)
        if args:
            first_arg = args[0]
            for sp in self._subparsers:
                if sp.identifier == first_arg:
                    # Đệ quy parse phần còn lại
                    parsed_result = sp.subparser.parse(args[1:])
                    if parsed_result and sp.handler:
                        sp.handler(parsed_result)
                    return parsed_result

        # 2. Xử lý các flags và parameters
        processed_args_indices = set()

        # Quét Flag trước
        for i, arg in enumerate(args):
            if i in processed_args_indices: continue

            matched_flag = False
            for cmd in self._commands:
                if cmd.type == CommandType.FLAG and cmd.identifier == arg:
                    result_dict[cmd.name] = True
                    processed_args_indices.add(i)
                    matched_flag = True
                    break
                elif cmd.type == CommandType.PARAMETERIZED_FLAG and cmd.identifier == arg:
                    if i + 1 >= len(args):
                        IO.error(f"Missing parameter for flag {IO.Fore.LIGHTYELLOW_EX}{cmd.name}{IO.Style.RESET_ALL}")
                        return None
                    
                    result_dict[cmd.name] = args[i+1]
                    processed_args_indices.add(i)
                    processed_args_indices.add(i+1)
                    matched_flag = True
                    break
            
            # Nếu arg không phải flag, để dành cho parameter
            if not matched_flag:
                pass

        # Quét Parameters (các arg chưa được xử lý)
        param_cmds = [cmd for cmd in self._commands if cmd.type == CommandType.PARAMETER]
        param_idx = 0
        
        for i, arg in enumerate(args):
            if i in processed_args_indices: continue
            
            if param_idx < len(param_cmds):
                cmd = param_cmds[param_idx]
                result_dict[cmd.name] = arg
                processed_args_indices.add(i)
                param_idx += 1
            else:
                IO.error(f"Unknown argument: {IO.Fore.LIGHTYELLOW_EX}{arg}{IO.Style.RESET_ALL}")
                return None

        # 3. Validation: Kiểm tra xem các Parameter bắt buộc có đủ không
        for cmd in param_cmds:
            if result_dict[cmd.name] is None:
                IO.error(f"Missing required parameter: {IO.Fore.LIGHTYELLOW_EX}{cmd.name}{IO.Style.RESET_ALL}")
                return None

        # 4. Gán False cho các Flag không xuất hiện (thay vì None)
        for cmd in self._commands:
            if cmd.type == CommandType.FLAG and result_dict[cmd.name] is None:
                result_dict[cmd.name] = False

        # Trả về object kết quả (tương tự namespace của argparse)
        ResultClass = type('ParseResult', (object,), result_dict)
        return ResultClass()