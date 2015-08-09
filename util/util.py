import sys
import platform


if platform.system() == 'Windows':
    import msvcrt
else:
    import select
    import termios
    import tty


if platform.system() == 'Windows':
    class Char():

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            pass

        def getchar(self):
            if msvcrt.kbhit():
                return msvcrt.getch()
            else:
                return None
else:
    class Char():

        def __enter__(self):
            self._attr = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._attr)

        def getchar(self):
            if select.select([sys.stdin], [], [], 0):
                return sys.stdin.read(1)
            else:
                return None
