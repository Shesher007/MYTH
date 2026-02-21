import re

from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🧩 Esoteric Encodings & Ciphers CTF Tools
# ==============================================================================


@tool
async def morse_code_translator(text: str, to_morse: bool = True) -> str:
    """
    Translates text to Morse code or decodes Morse code to plaintext.
    Supports standard alphanumeric characters and common symbols.
    """
    try:
        morse_map = {
            "A": ".-",
            "B": "-...",
            "C": "-.-.",
            "D": "-..",
            "E": ".",
            "F": "..-.",
            "G": "--.",
            "H": "....",
            "I": "..",
            "J": ".---",
            "K": "-.-",
            "L": ".-..",
            "M": "--",
            "N": "-.",
            "O": "---",
            "P": ".--.",
            "Q": "--.-",
            "R": ".-.",
            "S": "...",
            "T": "-",
            "U": "..-",
            "V": "...-",
            "W": ".--",
            "X": "-..-",
            "Y": "-.--",
            "Z": "--..",
            "1": ".----",
            "2": "..---",
            "3": "...--",
            "4": "....-",
            "5": ".....",
            "6": "-....",
            "7": "--...",
            "8": "---..",
            "9": "----.",
            "0": "-----",
            " ": "/",
        }
        reverse_map = {v: k for k, v in morse_map.items()}

        if to_morse:
            result = " ".join(morse_map.get(c.upper(), "?") for c in text)
        else:
            result = "".join(reverse_map.get(c, "?") for c in text.split(" "))

        return format_industrial_result(
            "morse_code_translator",
            "Success",
            confidence=1.0,
            impact="LOW",
            raw_data={
                "input": text,
                "output": result,
                "mode": "to_morse" if to_morse else "from_morse",
            },
            summary=f"Morse translation complete. Result: {result[:50]}...",
        )
    except Exception as e:
        return format_industrial_result("morse_code_translator", "Error", error=str(e))


@tool
async def brute_force_rot_tester(ciphertext: str) -> str:
    """
    Applies all 25 possible ROT rotation offsets to the provided ciphertext.
    Useful for identifying ROT13 and other Caesar cipher variants in CTFs.
    """
    try:
        rotations = []
        for shift in range(1, 26):
            rotated = ""
            for char in ciphertext:
                if char.isalpha():
                    base = ord("A") if char.isupper() else ord("a")
                    rotated += chr((ord(char) - base + shift) % 26 + base)
                else:
                    rotated += char
            rotations.append({"shift": shift, "result": rotated})

        return format_industrial_result(
            "brute_force_rot_tester",
            "Analysis Complete",
            confidence=1.0,
            impact="LOW",
            raw_data={"all_rotations": rotations},
            summary="Caesar/ROT brute-force finished. Applied 25 rotation variants to identified potential cleartext.",
        )
    except Exception as e:
        return format_industrial_result("brute_force_rot_tester", "Error", error=str(e))


@tool
async def brainfuck_interpreter(code: str, input_data: str = "") -> str:
    """
    Executes Brainfuck code with strict pointer boundary and step limit safety.
    """
    try:
        CELL_COUNT = 30000
        cells = [0] * CELL_COUNT
        ptr = 0
        output = ""
        input_ptr = 0

        # Pre-process loops
        loop_map = {}
        stack = []
        for i, char in enumerate(code):
            if char == "[":
                stack.append(i)
            elif char == "]":
                if not stack:
                    return "Error: Unmatched ']'"
                start = stack.pop()
                loop_map[start] = i
                loop_map[i] = start
        if stack:
            return "Error: Unmatched '['"

        pc = 0
        steps = 0
        MAX_STEPS = 500000  # Safety limit
        while pc < len(code) and steps < MAX_STEPS:
            steps += 1
            char = code[pc]

            # Robustness Pass: Pointer Boundary Checks
            if char == ">":
                ptr = (ptr + 1) % CELL_COUNT
            elif char == "<":
                ptr = (ptr - 1) % CELL_COUNT
            elif char == "+":
                cells[ptr] = (cells[ptr] + 1) % 256
            elif char == "-":
                cells[ptr] = (cells[ptr] - 1) % 256
            elif char == ".":
                output += chr(cells[ptr])
            elif char == ",":
                if input_ptr < len(input_data):
                    cells[ptr] = ord(input_data[input_ptr])
                    input_ptr += 1
                else:
                    cells[ptr] = 0
            elif char == "[":
                if cells[ptr] == 0:
                    pc = loop_map[pc]
            elif char == "]":
                if cells[ptr] != 0:
                    pc = loop_map[pc]
            pc += 1

        if steps >= MAX_STEPS:
            return format_industrial_result(
                "brainfuck_interpreter",
                "Timeout",
                error="Exceeded maximum execution steps (Possible infinite loop).",
            )

        return format_industrial_result(
            "brainfuck_interpreter",
            "Success",
            confidence=1.0,
            raw_data={"output": output, "steps": steps},
            summary=f"Brainfuck execution finished in {steps} steps with pointer safety. Output: {output[:50]}",
        )
    except Exception as e:
        return format_industrial_result(
            "brainfuck_interpreter", "Runtime Error", error=str(e)
        )


@tool
async def baconian_cipher_solver(
    ciphertext: str, mapping_a: str = "A", mapping_b: str = "B"
) -> str:
    """
    Decodes a Baconian cipher (A/B style) with input validation.
    """
    try:
        if not ciphertext:
            raise ValueError("Ciphertext is empty.")

        alphabet_full = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        clean = re.sub(
            f"[^{re.escape(mapping_a)}{re.escape(mapping_b)}]", "", ciphertext.upper()
        )

        if not clean:
            raise ValueError(
                f"No valid Baconian characters ({mapping_a}/{mapping_b}) found."
            )

        decoded = ""
        for i in range(0, len(clean) - len(clean) % 5, 5):
            chunk = clean[i : i + 5]
            binary = chunk.replace(mapping_a, "0").replace(mapping_b, "1")
            idx = int(binary, 2)
            decoded += alphabet_full[idx] if idx < 26 else "?"

        return format_industrial_result(
            "baconian_cipher_solver",
            "Decoded",
            confidence=0.9,
            raw_data={"decoded": decoded},
            summary=f"Baconian decoding complete with character validation: {decoded[:50]}...",
        )
    except ValueError as e:
        return format_industrial_result(
            "baconian_cipher_solver", "Validation Error", error=str(e)
        )
    except Exception as e:
        return format_industrial_result("baconian_cipher_solver", "Error", error=str(e))


@tool
async def base91_decoder(encoded_str: str) -> str:
    """
    Decodes a Base91 encoded string.
    Commonly seen in CTFs for high-density binary-to-text encoding.
    """
    try:
        base91_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
        decode_table = {c: i for i, c in enumerate(base91_alphabet)}

        v = -1
        b = 0
        n = 0
        out = bytearray()
        for char in encoded_str:
            if char not in decode_table:
                continue
            c = decode_table[char]
            if v < 0:
                v = c
            else:
                v += c * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while True:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                    if not n > 7:
                        break
                v = -1
        if v + 1:
            out.append((b | v << n) & 255)

        return format_industrial_result(
            "base91_decoder",
            "Decoded",
            confidence=1.0,
            raw_data={"decoded_hex": out.hex()},
            summary=f"Base91 decoding complete. Extracted {len(out)} bytes.",
        )
    except Exception as e:
        return format_industrial_result("base91_decoder", "Error", error=str(e))
