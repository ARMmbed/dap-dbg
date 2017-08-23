"""
Abstraction of a Win32 named pipe.
"""
import io

import win32con
import win32file
import win32pipe

class FIFOServer(io.RawIOBase):
    def __init__(self, name):
        # TODO: allow security settings to be configured
        self.path = r'\\.\pipe\%s' % name
        self.pipe = win32pipe.CreateNamedPipe(
            self.path,
            win32pipe.PIPE_ACCESS_DUPLEX | win32con.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            5, 65536, 65536,
            300,
            None
        )
    
    def connect(self):
        win32pipe.ConnectNamedPipe(self.pipe, None)
    
    def write(self, data):
        win32file.WriteFile(self.pipe, data)
    
    def read(self):
        data = win32file.ReadFile(self.pipe, 4096)

        if data[0] == 0:
            return data[1]
        else:
            raise IOError(data[0])
    
    def close(self):
        win32file.FlushFileBuffers(self.pipe)
        win32pipe.DisconnectNamedPipe(self.pipe)
        win32api.CloseHandle(self.pipe)

class FIFOClient(io.RawIOBase):
    def __init__(self, path):
        self.pipe = win32file.CreateFile(
            path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None,
            win32file.OPEN_EXISTING,
            0, None
        )
    
    def write(self, data):
        win32file.WriteFile(self.pipe, data)

    def read(self):
        data = win32file.ReadFile(self.pipe, 4096)

        if data[0] == 0:
            return data[1]
        else:
            raise IOError(data[0])
    
    def close(self):
        win32file.FlushFileBuffers(self.pipe)
        win32pipe.DisconnectNamedPipe(self.pipe)
        win32api.CloseHandle(self.pipe)
