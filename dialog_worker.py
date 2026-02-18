import tkinter as tk
from tkinter import filedialog
import sys
from myth_config import load_dotenv
load_dotenv()

def browse_folder():
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        folder_selected = filedialog.askdirectory()
        root.destroy()
        if folder_selected:
            print(folder_selected)
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as e:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    browse_folder()
