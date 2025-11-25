import sys
from typing import Optional, List
from .parser import CommandParser
from evillimiter.console.io import IO

class CommandMenu:
    def __init__(self):
        self.prompt = '>>> '
        self.parser = CommandParser()
        self._active = False

    def argument_handler(self, args):
        """
        Phương thức này sẽ được override bởi lớp con (MainMenu)
        để xử lý các lệnh cụ thể.
        """
        pass

    def interrupt_handler(self):
        """
        Xử lý khi người dùng nhấn Ctrl+C (KeyboardInterrupt).
        Mặc định là dừng menu.
        """
        self.stop()

    def start(self):
        """
        Bắt đầu vòng lặp nhập liệu (REPL loop).
        """
        self._active = True

        while self._active:
            try:
                # Sử dụng IO.input để đồng bộ giao diện
                command_str = IO.input(self.prompt)
                
                # Nếu người dùng chỉ nhấn Enter (chuỗi rỗng), bỏ qua
                if not command_str or not command_str.strip():
                    continue

                # Tách chuỗi lệnh
                args = command_str.split()
                
                # Gửi vào parser xử lý
                parsed_args = self.parser.parse(args)
                
                # Nếu parse thành công (không lỗi cú pháp), gọi handler
                if parsed_args is not None:
                    self.argument_handler(parsed_args)

            except KeyboardInterrupt:
                # Bắt Ctrl+C
                self.interrupt_handler()
                break
            
            except EOFError:
                # Bắt Ctrl+D (End of File) - Thường gặp trên Linux/Mac
                IO.spacer()
                self.stop()
                break
                
            except Exception as e:
                # Bắt lỗi không mong muốn để tránh crash chương trình
                IO.error(f"An unexpected error occurred: {e}")

    def stop(self):
        """
        Dừng vòng lặp menu.
        """
        self._active = False