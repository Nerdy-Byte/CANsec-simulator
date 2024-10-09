import subprocess
import time


def run_supplicant(script_name):
    process = subprocess.Popen(['python3', script_name])
    return process


if __name__ == "__main__":
    process1 = run_supplicant('suplicant1.py')
    time.sleep(2)
    process2 = run_supplicant('suplicant2.py')
    process1.wait()
    process2.wait()
