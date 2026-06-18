"""
================================================================================
  crypto_gui.py  v5  —  Crypto Toolkit GUI  (clean edition)
================================================================================
  Requires:  crypto_lib.py  +  pip install cryptography
  Optional:  rockyou.txt in the same folder (for breach database check)

  Run:
      python crypto_gui.py

  Two tabs:
    [1] Home — Password Security Center
          • Live password analysis (strength, crack time, breach check)
          • Secure password suggestion (length + 4 toggles)
    [2] Crypto Toolkit
          • Encoding  : Base64, Hex, URL
          • Hashing   : SHA-256, SHA-512, Salted Hash
          • Symmetric : AES (ECB/CBC/CFB/OFB/CTR/GCM), DES, 3DES
          • Asymmetric: RSA-1024, RSA-2048

  Changes vs v4:
    • Removed duplicate load_rockyou()     — now imported from crypto_lib
    • Removed duplicate estimate_crack_time() — now imported from crypto_lib
    • Removed duplicate rsa_pub_hex()      — now imported from crypto_lib
    • Removed duplicate rsa_priv_hex()     — now imported from crypto_lib
    • Removed duplicate rsa_from_hex()     — now imported from crypto_lib
    • Removed duplicate rsa_to_hex()       — no longer needed
    • Removed 'Exclude chars' field        — simplified PasswordGenerator
    • Removed 'No repeats' checkbox        — simplified PasswordGenerator
    • Removed unused imports (math, time)
    • All dead code, redundant comments, and unused variables cleaned up
================================================================================
"""

# ── Standard library ──────────────────────────────────────────────────────────
import os                               # os.urandom() for key / IV generation
import sys                              # sys.exit() on import failure
import tkinter as tk                    # GUI toolkit (built-in, no install)
from tkinter import ttk, messagebox    # themed widgets + pop-up dialogs

# ── Import everything we need from our crypto library ─────────────────────────
try:
    from crypto_lib import (
        # Encoding
        base64_encode, base64_decode,
        hex_encode, hex_decode,
        url_encode, url_decode,
        # Hashing
        sha256_hex, sha512_hex,
        salted_hash,
        # Symmetric ciphers
        AES, DES, TripleDES,
        # Asymmetric cipher
        RSA,
        # RSA key helpers (live in crypto_lib — no duplicates in GUI)
        rsa_pub_hex, rsa_priv_hex, rsa_from_hex,
        # Password tools (live in crypto_lib — no duplicates in GUI)
        PasswordGenerator,
        estimate_crack_time,
        load_rockyou,
        # Shared byte helpers
        _bytes_to_int, _int_to_bytes,
    )
except ImportError as e:
    print(f"ERROR: Could not import crypto_lib.py — {e}")
    print("Make sure crypto_lib.py is in the same folder as this file.")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  THEME  —  all colours in one dict for easy restyling later
# ══════════════════════════════════════════════════════════════════════════════
C = {
    # ── Backgrounds ───────────────────────────────────────────────────────────
    "bg":       "#1a1a2e",   # main window background     (deep navy-black)
    "panel":    "#22223a",   # card / frame background    (dark blue-purple)
    "panel2":   "#2a2a48",   # nested card background     (slightly lighter)
    "border":   "#7c3aed",   # divider lines and borders  (vivid purple)
    # ── Accent colours ────────────────────────────────────────────────────────
    "accent":   "#ff6b00",   # orange — primary accent, selected items, titles
    "accent2":  "#a855f7",   # purple — success, copy buttons, output text
    # ── Status colours ────────────────────────────────────────────────────────
    "danger":   "#f87171",   # red    — weak passwords, errors
    "warn":     "#fb923c",   # orange — fair passwords, warnings
    "ok":       "#c084fc",   # light purple — strong passwords, success
    # ── Text ──────────────────────────────────────────────────────────────────
    "text":     "#f1f0ff",   # primary text               (near-white with purple tint)
    "muted":    "#8b7aa8",   # secondary / hint text      (muted purple-grey)
    # ── Inputs & buttons ──────────────────────────────────────────────────────
    "input_bg": "#13131f",   # text input background      (near-black, dark navy)
    "btn":      "#ff6b00",   # default button             (orange)
    "btn2":     "#3d2e6b",   # secondary / reset button   (dark purple)
}

# Font tuples — Consolas keeps a consistent monospace look throughout
FT = ("Consolas", 13, "bold")   # card / section title
FL = ("Consolas", 10)           # field label
FM = ("Consolas", 10)           # monospace input / output text
FB = ("Consolas", 10, "bold")   # button text
FS = ("Consolas",  9)           # small hint / badge text
FH = ("Consolas", 18, "bold")   # large heading on Home page


#  SHARED WIDGET HELPERS
#  Small utility functions used across both tabs.

# Create a flat dark-themed tk.Button.
def mkbtn(parent, text, cmd, color=None, width=16):
    return tk.Button(
        parent, text=text, command=cmd,
        bg=color or C["btn"],               # accent purple if no colour given
        fg=C["text"],
        activebackground=C["accent"],
        activeforeground=C["text"],
        relief="flat",                       # no 3-D raised look
        cursor="hand2",                      # pointer cursor on hover
        font=FB, padx=8, pady=5, width=width,
    )

# Draw a 1 px horizontal divider rule inside a panel
def mksep(parent):
    tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", pady=8)

#Read all content from a tk.Text widget (strips the trailing newline Tk adds)
def get_text(widget) -> str:
    return widget.get("1.0", "end-1c")

#Replace all content in a tk.Text widget with new text
def set_text(widget, text: str):
    widget.config(state="normal")   # widget must be writable to edit
    widget.delete("1.0", "end")     # wipe existing content
    widget.insert("1.0", str(text)) # write new content

#Copy text to the OS clipboard
#Flashes the button green for 1.5 s if one is provided.
def clip_copy(root, text: str, button=None):

    root.clipboard_clear()
    root.clipboard_append(text)
    if button:
        orig_text = button.cget("text")
        orig_bg   = button.cget("bg")
        button.config(text="Copied!", bg=C["accent2"])
        button.after(1500, lambda: button.config(text=orig_text, bg=orig_bg))


def safe_decode(data: bytes) -> str:
    """
    Convert bytes to a displayable string.
    Returns clean UTF-8 text if possible; otherwise returns '[hex] ...'
    so the user never sees replacement characters (e.g. ï¿½).
    """
    try:
        text = data.decode("utf-8")
        if all(c.isprintable() or c in "\n\r\t" for c in text):
            return text             # all characters are readable — return as text
    except UnicodeDecodeError:
        pass                        # not valid UTF-8 — fall through
    return "[hex] " + hex_encode(data)  # safe hex fallback


#  AES MODE TABLE
#  Single source of truth for IV requirements per AES mode.
#  Used by both the IV visibility logic and the IV validation logic.

AES_MODE_IV = {
    # mode : (needs_iv, iv_label,            iv_byte_len, hint_for_user)
    "ECB"  : (False, "",                     0,  "ECB has no IV — each block encrypted independently."),
    "CBC"  : (True,  "IV  (16 bytes):",      16, "CBC requires a 16-byte IV (32 hex chars)."),
    "CFB"  : (True,  "IV  (16 bytes):",      16, "CFB requires a 16-byte IV (32 hex chars)."),
    "OFB"  : (True,  "IV  (16 bytes):",      16, "OFB requires a 16-byte IV (32 hex chars)."),
    "CTR"  : (True,  "Nonce (16 bytes):",    16, "CTR requires a 16-byte nonce (32 hex chars)."),
    "GCM"  : (True,  "Nonce (12 bytes):",    12, "GCM requires a 12-byte nonce (24 hex chars)."),
}


#------------------------------------------------T-AB 1 — HOME PAGE-------------------------------------

class HomePage(tk.Frame):
    """
    Landing page: password analyzer + secure password suggestion.

    Sections:
      A) Analyzer  — live strength score, crack time, breach DB check
      B) Suggestion — generate a password with length + 4 type toggles
    """

    def __init__(self, parent, root):
        super().__init__(parent, bg=C["bg"])
        self.root    = root
        self.pg      = PasswordGenerator()  # one shared generator instance
        self.rockyou = load_rockyou()       # load breach DB once at startup
        self._build()

    #Build

    def _build(self):
        # Page heading
        tk.Label(self, text="Password Security, Try your password!!",
                 font=FH, bg=C["bg"], fg=C["accent"],
                 ).pack(anchor="w", padx=24, pady=(20, 2))
        tk.Label(self,
                 text="Analyze strength, check breach databases, and generate a secure password.",
                 font=FS, bg=C["bg"], fg=C["muted"],
                 ).pack(anchor="w", padx=24)

        self._build_analyzer()      # Section A
        self._build_suggestion()    # Section B

    #Password input card + 4 result metric cards + strength bar
    def _build_analyzer(self):
        card  = tk.Frame(self, bg=C["panel"])
        card.pack(fill="x", padx=24, pady=(16, 0))
        inner = tk.Frame(card, bg=C["panel"])
        inner.pack(fill="x", padx=20, pady=16)

        tk.Label(inner, text="Write your Password",
                 font=FT, bg=C["panel"], fg=C["text"]).pack(anchor="w", pady=(0, 10))

        # Input row: password entry + Show/Hide + Analyze
        inp_row = tk.Frame(inner, bg=C["panel"])
        inp_row.pack(fill="x")
        tk.Label(inp_row, text="Password:", font=FL,
                 bg=C["panel"], fg=C["muted"], width=12, anchor="w").pack(side="left")

        self.pwd_var   = tk.StringVar()
        self.show_pwd  = tk.BooleanVar(value=False)  # tracks visible/hidden state
        self.pwd_entry = tk.Entry(
            inp_row, textvariable=self.pwd_var, show="•",  # hidden by default
            bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
            relief="flat", font=FM, bd=6)
        self.pwd_entry.pack(side="left", fill="x", expand=True, ipady=5)

        self.show_btn = mkbtn(inp_row, "Show", self._toggle_show,
                              color=C["btn2"], width=6)
        self.show_btn.pack(side="left", padx=(6, 0))

        mkbtn(inp_row, "Analyze", self._analyze,
              color=C["accent"], width=10).pack(side="left", padx=(6, 0))

        # Live update: re-analyze on every keystroke
        self.pwd_var.trace_add("write", lambda *_: self._analyze())

        mksep(inner)

        # 2×2 result card grid 
        grid = tk.Frame(inner, bg=C["panel"])
        grid.pack(fill="x")
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        #Small titled metric card. Returns the value Label
        def result_card(parent, row, col, title):
            f = tk.Frame(parent, bg=C["panel2"], padx=12, pady=10)
            f.grid(row=row, column=col, padx=6, pady=6, sticky="ew")
            tk.Label(f, text=title, font=FS,
                     bg=C["panel2"], fg=C["muted"]).pack(anchor="w")
            val = tk.Label(f, text="—", font=FT, bg=C["panel2"], fg=C["text"])
            val.pack(anchor="w", pady=(4, 0))
            return val

        self.r_rating = result_card(grid, 0, 0, "Strength Rating")
        self.r_crack  = result_card(grid, 0, 1, "Brute-Force Crack Time")
        self.r_breach = result_card(grid, 1, 0, "In Breach Database?")
        self.r_length = result_card(grid, 1, 1, "Password Length")

        # Tips label
        self.r_tips = tk.Label(
            inner, text="", font=FS, bg=C["panel"],
            fg=C["warn"], wraplength=580, justify="left")
        self.r_tips.pack(anchor="w", pady=(6, 0))

        # Strength progress bar (canvas rectangle)
        bar_row = tk.Frame(inner, bg=C["panel"])
        bar_row.pack(fill="x", pady=(8, 0))
        tk.Label(bar_row, text="Strength:", font=FS,
                 bg=C["panel"], fg=C["muted"]).pack(side="left")
        self.strength_bar = tk.Canvas(
            bar_row, height=12, bg=C["border"],
            highlightthickness=0, width=400)
        self.strength_bar.pack(side="left", padx=8)
        self.bar_pct = tk.Label(bar_row, text="0%", font=FS,
                                bg=C["panel"], fg=C["muted"])
        self.bar_pct.pack(side="left")
        #Password suggestion card: length slider + 4 type toggles + output
    def _build_suggestion(self):
        card  = tk.Frame(self, bg=C["panel"])
        card.pack(fill="x", padx=24, pady=(12, 24))
        inner = tk.Frame(card, bg=C["panel"])
        inner.pack(fill="x", padx=20, pady=16)

        tk.Label(inner, text="Get a Secure Password Suggestion",
                 font=FT, bg=C["panel"], fg=C["text"]).pack(anchor="w", pady=(0, 10))

        # Configuration grid
        cfg = tk.Frame(inner, bg=C["panel"])
        cfg.pack(fill="x")

        # Length slider
        tk.Label(cfg, text="Length:", font=FL,
                 bg=C["panel"], fg=C["muted"]).grid(
                     row=0, column=0, sticky="w", padx=(0, 6))
        self.sug_len_var = tk.IntVar(value=16)
        self.sug_len_lbl = tk.Label(cfg, text="16", font=FL,
                                    bg=C["panel"], fg=C["accent"], width=3)
        self.sug_len_lbl.grid(row=0, column=2, sticky="w")
        tk.Scale(
            cfg, from_=8, to=64, orient="horizontal",
            variable=self.sug_len_var,
            command=lambda v: self.sug_len_lbl.config(text=str(v)),
            bg=C["panel"], fg=C["text"], troughcolor=C["border"],
            highlightthickness=0, bd=0, length=200, showvalue=False,
        ).grid(row=0, column=1, sticky="w", padx=(0, 4))

        # 4 character-type checkboxes (simplified — no exclude/no-repeat)
        self.sug_upper   = tk.BooleanVar(value=True)
        self.sug_lower   = tk.BooleanVar(value=True)
        self.sug_digits  = tk.BooleanVar(value=True)
        self.sug_special = tk.BooleanVar(value=True)

        for col, (txt, var) in enumerate([
            ("Uppercase",   self.sug_upper),
            ("Lowercase",   self.sug_lower),
            ("Digits",      self.sug_digits),
            ("Special (eg.:!@#)", self.sug_special),
        ]):
            tk.Checkbutton(
                cfg, text=txt, variable=var,
                bg=C["panel"], fg=C["text"],
                selectcolor=C["input_bg"],
                activebackground=C["panel"], font=FS,
            ).grid(row=1, column=col, sticky="w", pady=(8, 0))

        # Result row: generated password + Copy button
        res_row = tk.Frame(inner, bg=C["panel"])
        res_row.pack(fill="x", pady=(14, 0))
        self.sug_var = tk.StringVar()
        tk.Entry(res_row, textvariable=self.sug_var,
                 bg=C["input_bg"], fg=C["accent2"],
                 insertbackground=C["text"], relief="flat",
                 font=("Consolas", 12, "bold"), bd=6, state="readonly",
                 ).pack(side="left", fill="x", expand=True, ipady=6)
        self.sug_copy_btn = mkbtn(
            res_row, "Copy", self._copy_suggestion,
            color=C["accent2"], width=8)
        self.sug_copy_btn.pack(side="left", padx=(8, 0))

        # Generate button
        mkbtn(inner, "Generate Suggestion", self._generate_suggestion,
              width=22).pack(anchor="w", pady=(10, 0))

    #─ Event handlers

    def _toggle_show(self):
        """Toggle the password entry between hidden (•) and visible."""
        if self.show_pwd.get():
            self.pwd_entry.config(show="•")
            self.show_btn.config(text="Show")
            self.show_pwd.set(False)
        else:
            self.pwd_entry.config(show="")
            self.show_btn.config(text="Hide")
            self.show_pwd.set(True)

    def _analyze(self):
        """
        Run all checks on the current password and update the 4 result cards.
        Called automatically on every keystroke via StringVar trace.

        Checks (all delegated to crypto_lib.py functions):
          1. pg.strength()        — score 0-100, label, feedback tips
          2. estimate_crack_time() — brute-force time string
          3. rockyou set lookup   — O(1) breach database membership test
          4. len(pwd)             — character count
        """
        pwd = self.pwd_var.get()

        if not pwd:
            # Reset everything when the field is empty
            for lbl in (self.r_rating, self.r_crack, self.r_breach, self.r_length):
                lbl.config(text="—", fg=C["text"])
            self.r_tips.config(text="")
            self.strength_bar.delete("all")
            self.bar_pct.config(text="0%")
            return

        # ── Strength score (check 1) ───────────────────────────────────────────
        result = self.pg.strength(pwd)
        score  = result["score"]    # 0–100
        label  = result["label"]    # Weak / Fair / Strong / Very Strong
        tips   = result["feedback"] # list of improvement strings

        color = (C["danger"] if score < 40 else
                 C["warn"]   if score < 60 else
                 C["ok"]     if score < 80 else C["accent2"])

        self.r_rating.config(text=label, fg=color)

        # ── Crack time estimate (check 2) ─────────────────────────────────────
        self.r_crack.config(text=estimate_crack_time(pwd), fg=C["text"])

        # ── Breach database check (check 3) ───────────────────────────────────
        if self.rockyou:
            if pwd.lower() in self.rockyou:     # O(1) set membership test
                self.r_breach.config(text="YES — Found in database!", fg=C["danger"])
            else:
                self.r_breach.config(text="Not found  ✓", fg=C["ok"])
        else: # error handling 
            self.r_breach.config(text="rockyou.txt not found", fg=C["muted"])

        # Length (check 4)
        self.r_length.config(
            text=f"{len(pwd)} characters",
            fg=C["ok"] if len(pwd) >= 12 else C["warn"])

        # Feedback tips
        self.r_tips.config(
            text="Tips: " + " | ".join(tips) if tips else "No suggestions — looks good!",
            fg=C["warn"] if tips else C["ok"])

        # Strength bar (proportional rectangle on canvas)
        self.strength_bar.delete("all")
        self.strength_bar.create_rectangle(
            0, 0, int(400 * score / 100), 12,
            fill=color, outline="")
        self.bar_pct.config(text=f"{score}%", fg=color)

    def _generate_suggestion(self):
        """Push the 4 toggle settings into PasswordGenerator and call generate()."""
        self.pg.use_uppercase = self.sug_upper.get()
        self.pg.use_lowercase = self.sug_lower.get()
        self.pg.use_digits    = self.sug_digits.get()
        self.pg.use_special   = self.sug_special.get()
        # Set minimum-1 for each enabled category so policy is always satisfied
        self.pg.min_uppercase = 1 if self.sug_upper.get()   else 0
        self.pg.min_lowercase = 1 if self.sug_lower.get()   else 0
        self.pg.min_digits    = 1 if self.sug_digits.get()  else 0
        self.pg.min_special   = 1 if self.sug_special.get() else 0
        try:
            self.sug_var.set(self.pg.generate(self.sug_len_var.get()))
        except ValueError as e:
            messagebox.showerror("Generator Error", str(e))

    def _copy_suggestion(self):
        """Copy the generated suggestion to the clipboard."""
        if self.sug_var.get():
            clip_copy(self.root, self.sug_var.get(), self.sug_copy_btn)


#-------------------TAB 2 — CRYPTO TOOLKIT------------------------

class CryptoToolkit(tk.Frame):
    """
    Full cryptographic toolkit.
    Layout: fixed-width sidebar (algorithm list) + right panel (controls + I/O).

    Persistent selection: exportselection=False + <FocusOut> binding ensures
    the selected algorithm is never lost when the user clicks elsewhere.
    """

    # Algorithm registry: name → (category_label, algo_type)
    # algo_type drives which control block is shown in the right panel
    ALGOS = {
        "Base64"      : ("Encoding",   "encoding"),
        "Hex"         : ("Encoding",   "encoding"),
        "URL"         : ("Encoding",   "encoding"),
        "SHA-256"     : ("Hashing",    "hash"),
        "SHA-512"     : ("Hashing",    "hash"),
        "Salted Hash" : ("Hashing",    "hash"),
        "AES"         : ("Symmetric",  "aes"),
        "DES"         : ("Symmetric",  "des"),
        "3DES"        : ("Symmetric",  "3des"),
        "RSA-1024"    : ("Asymmetric", "rsa"),
        "RSA-2048"    : ("Asymmetric", "rsa"),
    }

    def __init__(self, parent, root):
        super().__init__(parent, bg=C["bg"])
        self.root         = root
        self._rsa_cache   = {}  # {bits: RSA instance} — avoids regenerating
        self._current_idx = 0   # index of the currently selected algorithm
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        tk.Label(self, text="  Crypto Toolkit", font=FT,
                 bg=C["bg"], fg=C["accent"]).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(self, text="Encrypt, encode, and hash with every algorithm.",
                 font=FS, bg=C["bg"], fg=C["muted"]).pack(anchor="w", padx=20)

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=20, pady=10)
        self._build_sidebar(body)
        self._build_right(body)
        self._select(0)             # highlight the first algorithm on startup

    def _build_sidebar(self, parent):
        """
        Fixed-width left sidebar with the algorithm Listbox.

        Key settings:
          exportselection=False — prevents focus loss from clearing the highlight
          <FocusOut> binding    — restores the stored selection if Tk clears it
        """
        side = tk.Frame(parent, bg=C["panel"], width=150)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)  # keep fixed width

        tk.Label(side, text="Algorithm", font=FL,
                 bg=C["panel"], fg=C["muted"]).pack(pady=(12, 4), padx=10, anchor="w")

        self.listbox = tk.Listbox(
            side,
            selectmode="single",
            bg=C["input_bg"],
            fg=C["text"],
            selectbackground=C["accent"],   # purple row highlight
            selectforeground=C["text"],
            font=FM,
            relief="flat",
            highlightthickness=0,
            bd=0,
            activestyle="none",             # no dotted border on hover
            exportselection=False,          # NEVER lose selection on focus change
        )
        for name in self.ALGOS:
            self.listbox.insert("end", "  " + name)  # indent for visual padding

        self.listbox.pack(fill="both", expand=True, padx=8, pady=(0, 12))
        self.listbox.bind("<<ListboxSelect>>", self._on_select)
        self.listbox.bind("<FocusOut>", self._restore_selection)  # restore on blur

    def _build_right(self, parent):
        """Right panel: header, algorithm-specific controls, shared I/O area."""
        self.right = tk.Frame(parent, bg=C["panel"])
        self.right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        p = tk.Frame(self.right, bg=C["panel"])
        p.pack(fill="both", expand=True, padx=18, pady=14)
        self._p = p

        # ── Header: algorithm name + category badge + Reset button ─────────────
        hdr = tk.Frame(p, bg=C["panel"])
        hdr.pack(fill="x")
        self.algo_title = tk.Label(hdr, text="", font=FT,
                                   bg=C["panel"], fg=C["accent"])
        self.algo_title.pack(side="left")
        self.cat_badge = tk.Label(hdr, text="", font=FS,
                                  bg=C["border"], fg=C["text"], padx=8, pady=2)
        self.cat_badge.pack(side="left", padx=10)
        mkbtn(hdr, "Reset Fields", self._reset,
              color=C["btn2"], width=12).pack(side="right")

        mksep(p)

        # ── Per-algorithm usage hint ───────────────────────────────────────────
        self.hint_lbl = tk.Label(p, text="", font=FS, bg=C["panel"], fg=C["muted"],
                                 wraplength=460, justify="left")
        self.hint_lbl.pack(anchor="w", pady=(0, 6))

        #  AES CONTROL BLOCK
        self.aes_frame = tk.Frame(p, bg=C["panel"])

        # Key row
        aes_kr = tk.Frame(self.aes_frame, bg=C["panel"])
        aes_kr.pack(fill="x", pady=(0, 4))
        tk.Label(aes_kr, text="Key (hex):", font=FL,
                 bg=C["panel"], fg=C["muted"], width=15, anchor="w").pack(side="left")
        self.aes_key_var = tk.StringVar()
        tk.Entry(aes_kr, textvariable=self.aes_key_var,
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
                 relief="flat", font=FM, bd=4,
                 ).pack(side="left", fill="x", expand=True, ipady=3)
        self.aes_ksz_var = tk.StringVar(value="16 bytes (AES-128)")
        ttk.Combobox(aes_kr, textvariable=self.aes_ksz_var,
                     values=["16 bytes (AES-128)",
                             "24 bytes (AES-192)",
                             "32 bytes (AES-256)"],
                     width=18, state="readonly", font=FS,
                     ).pack(side="left", padx=(6, 0))
        mkbtn(aes_kr, "Gen Key", self._aes_gen_key,
              width=8).pack(side="left", padx=(6, 0))

        # Mode row
        aes_mr = tk.Frame(self.aes_frame, bg=C["panel"])
        aes_mr.pack(fill="x", pady=(0, 4))
        tk.Label(aes_mr, text="Mode:", font=FL,
                 bg=C["panel"], fg=C["muted"], width=15, anchor="w").pack(side="left")
        self.aes_mode_var = tk.StringVar(value="CBC")
        ttk.Combobox(aes_mr, textvariable=self.aes_mode_var,
                     values=list(AES_MODE_IV.keys()),
                     width=8, state="readonly", font=FS,
                     ).pack(side="left")
        self.aes_mode_hint = tk.Label(aes_mr, text="", font=FS,
                                      bg=C["panel"], fg=C["muted"], wraplength=280)
        self.aes_mode_hint.pack(side="left", padx=(10, 0))
        # Trace: sync IV row whenever mode changes
        self.aes_mode_var.trace_add("write", lambda *_: self._aes_sync_iv())

        # IV row (shown/hidden depending on mode)
        self.aes_iv_row = tk.Frame(self.aes_frame, bg=C["panel"])
        self.aes_iv_lbl = tk.Label(self.aes_iv_row, text="IV:", font=FL,
                                   bg=C["panel"], fg=C["muted"], width=15, anchor="w")
        self.aes_iv_lbl.pack(side="left")
        self.aes_iv_var = tk.StringVar()
        tk.Entry(self.aes_iv_row, textvariable=self.aes_iv_var,
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
                 relief="flat", font=FM, bd=4,
                 ).pack(side="left", fill="x", expand=True, ipady=3)
        mkbtn(self.aes_iv_row, "Gen IV", self._aes_gen_iv,
              width=8).pack(side="left", padx=(6, 0))

        #  DES CONTROL BLOCK
        self.des_frame = tk.Frame(p, bg=C["panel"])

        des_kr = tk.Frame(self.des_frame, bg=C["panel"])
        des_kr.pack(fill="x", pady=(0, 4))
        tk.Label(des_kr, text="Key (hex, 8 B):", font=FL,
                 bg=C["panel"], fg=C["muted"], width=15, anchor="w").pack(side="left")
        self.des_key_var = tk.StringVar()
        tk.Entry(des_kr, textvariable=self.des_key_var,
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
                 relief="flat", font=FM, bd=4,
                 ).pack(side="left", fill="x", expand=True, ipady=3)
        mkbtn(des_kr, "Gen Key",
              lambda: self.des_key_var.set(hex_encode(os.urandom(8))),
              width=8).pack(side="left", padx=(6, 0))

        des_ir = tk.Frame(self.des_frame, bg=C["panel"])
        des_ir.pack(fill="x", pady=(0, 4))
        tk.Label(des_ir, text="IV (hex, 8 B):", font=FL,
                 bg=C["panel"], fg=C["muted"], width=15, anchor="w").pack(side="left")
        self.des_iv_var = tk.StringVar()
        tk.Entry(des_ir, textvariable=self.des_iv_var,
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
                 relief="flat", font=FM, bd=4,
                 ).pack(side="left", fill="x", expand=True, ipady=3)
        mkbtn(des_ir, "Gen IV",
              lambda: self.des_iv_var.set(hex_encode(os.urandom(8))),
              width=8).pack(side="left", padx=(6, 0))

        des_mr = tk.Frame(self.des_frame, bg=C["panel"])
        des_mr.pack(fill="x", pady=(0, 4))
        tk.Label(des_mr, text="Mode:", font=FL,
                 bg=C["panel"], fg=C["muted"], width=15, anchor="w").pack(side="left")
        self.des_mode_var = tk.StringVar(value="CBC")
        ttk.Combobox(des_mr, textvariable=self.des_mode_var,
                     values=["ECB", "CBC", "CFB", "OFB", "CTR"],
                     width=8, state="readonly", font=FS).pack(side="left")

        # ══════════════════════════════════════════════════════════════════════
        #  3DES CONTROL BLOCK
        # ══════════════════════════════════════════════════════════════════════
        self.tdes_frame = tk.Frame(p, bg=C["panel"])

        tdes_kr = tk.Frame(self.tdes_frame, bg=C["panel"])
        tdes_kr.pack(fill="x", pady=(0, 4))
        tk.Label(tdes_kr, text="Key (hex):", font=FL,
                 bg=C["panel"], fg=C["muted"], width=15, anchor="w").pack(side="left")
        self.tdes_key_var = tk.StringVar()
        tk.Entry(tdes_kr, textvariable=self.tdes_key_var,
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
                 relief="flat", font=FM, bd=4,
                 ).pack(side="left", fill="x", expand=True, ipady=3)
        self.tdes_ksz_var = tk.StringVar(value="16 bytes (2-key, 112-bit)")
        ttk.Combobox(tdes_kr, textvariable=self.tdes_ksz_var,
                     values=["16 bytes (2-key, 112-bit)", "24 bytes (3-key, 168-bit)"],
                     width=22, state="readonly", font=FS,
                     ).pack(side="left", padx=(6, 0))
        mkbtn(tdes_kr, "Gen Key", self._tdes_gen_key,
              width=8).pack(side="left", padx=(6, 0))

        # IV row — hidden when ECB is selected (via _tdes_sync_iv trace)
        self.tdes_iv_row = tk.Frame(self.tdes_frame, bg=C["panel"])
        self.tdes_iv_row.pack(fill="x", pady=(0, 4))
        tk.Label(self.tdes_iv_row, text="IV (hex, 8 B):", font=FL,
                 bg=C["panel"], fg=C["muted"], width=15, anchor="w").pack(side="left")
        self.tdes_iv_var = tk.StringVar()
        tk.Entry(self.tdes_iv_row, textvariable=self.tdes_iv_var,
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
                 relief="flat", font=FM, bd=4,
                 ).pack(side="left", fill="x", expand=True, ipady=3)
        mkbtn(self.tdes_iv_row, "Gen IV",
              lambda: self.tdes_iv_var.set(hex_encode(os.urandom(8))),
              width=8).pack(side="left", padx=(6, 0))

        tdes_mr = tk.Frame(self.tdes_frame, bg=C["panel"])
        tdes_mr.pack(fill="x", pady=(0, 4))
        tk.Label(tdes_mr, text="Mode:", font=FL,
                 bg=C["panel"], fg=C["muted"], width=15, anchor="w").pack(side="left")
        self.tdes_mode_var = tk.StringVar(value="CBC")
        ttk.Combobox(tdes_mr, textvariable=self.tdes_mode_var,
                     values=["ECB", "CBC", "CFB", "OFB", "CTR"],
                     width=8, state="readonly", font=FS).pack(side="left")
        # Trace: show/hide IV row when ECB selected
        self.tdes_mode_var.trace_add("write", lambda *_: self._tdes_sync_iv())

        # ══════════════════════════════════════════════════════════════════════
        #  RSA CONTROL BLOCK
        #  Two fields only: Public Key hex + Private Key hex.
        #  rsa_pub_hex / rsa_priv_hex / rsa_from_hex imported from crypto_lib.
        # ══════════════════════════════════════════════════════════════════════
        self.rsa_frame = tk.Frame(p, bg=C["panel"])

        rsa_top = tk.Frame(self.rsa_frame, bg=C["panel"])
        rsa_top.pack(fill="x", pady=(0, 8))
        self.rsa_status = tk.Label(rsa_top,
                                   text="Paste your keys below, or click Generate.",
                                   font=FS, bg=C["panel"], fg=C["muted"])
        self.rsa_status.pack(side="left")
        mkbtn(rsa_top, "Generate Key Pair", self._rsa_generate,
              width=18).pack(side="right")

        rsa_pub_r = tk.Frame(self.rsa_frame, bg=C["panel"])
        rsa_pub_r.pack(fill="x", pady=(0, 4))
        tk.Label(rsa_pub_r, text="Public Key (hex):", font=FL,
                 bg=C["panel"], fg=C["muted"], width=18, anchor="w").pack(side="left")
        self.rsa_pub_var = tk.StringVar()
        tk.Entry(rsa_pub_r, textvariable=self.rsa_pub_var,
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
                 relief="flat", font=FM, bd=4,
                 ).pack(side="left", fill="x", expand=True, ipady=3)

        rsa_prv_r = tk.Frame(self.rsa_frame, bg=C["panel"])
        rsa_prv_r.pack(fill="x", pady=(0, 4))
        tk.Label(rsa_prv_r, text="Private Key (hex):", font=FL,
                 bg=C["panel"], fg=C["muted"], width=18, anchor="w").pack(side="left")
        self.rsa_prv_var = tk.StringVar()
        tk.Entry(rsa_prv_r, textvariable=self.rsa_prv_var,
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["text"],
                 relief="flat", font=FM, bd=4,
                 ).pack(side="left", fill="x", expand=True, ipady=3)
        tk.Label(rsa_prv_r, text="(needed for decrypt)",
                 font=FS, bg=C["panel"], fg=C["muted"]).pack(side="left", padx=(8, 0))

        # ── Shared I/O area ────────────────────────────────────────────────────
        mksep(p)
        tk.Label(p, text="Input", font=FL,
                 bg=C["panel"], fg=C["muted"]).pack(anchor="w")
        self.input_text = tk.Text(
            p, height=4, bg=C["input_bg"], fg=C["text"],
            insertbackground=C["text"], relief="flat", font=FM, bd=6, wrap="word")
        self.input_text.pack(fill="x", pady=(2, 6))

        act = tk.Frame(p, bg=C["panel"])
        act.pack(fill="x", pady=(0, 6))
        mkbtn(act, "Encrypt / Encode / Hash",
              self._do_encrypt, width=24).pack(side="left", padx=(0, 8))
        self.dec_btn = mkbtn(act, "Decrypt / Decode",
                             self._do_decrypt, color=C["btn2"], width=18)
        self.dec_btn.pack(side="left")

        tk.Label(p, text="Output", font=FL,
                 bg=C["panel"], fg=C["muted"]).pack(anchor="w")
        out_row = tk.Frame(p, bg=C["panel"])
        out_row.pack(fill="x")
        self.output_text = tk.Text(
            out_row, height=5, bg=C["input_bg"], fg=C["accent2"],
            insertbackground=C["text"], relief="flat", font=FM, bd=6, wrap="word")
        self.output_text.pack(side="left", fill="x", expand=True)
        self.copy_out_btn = mkbtn(out_row, "Copy", self._copy_out,
                                  color=C["btn2"], width=6)
        self.copy_out_btn.pack(side="left", padx=(6, 0), anchor="n")

    # ── Selection management ──────────────────────────────────────────────────

    def _select(self, idx: int):
        """Highlight row `idx` in the listbox and update the right panel."""
        self._current_idx = idx
        self.listbox.selection_clear(0, "end")
        self.listbox.selection_set(idx)
        self.listbox.activate(idx)
        self._show_algo(idx)

    def _on_select(self, _=None):
        """Called by <<ListboxSelect>>. Delegates to _select() to store the index."""
        sel = self.listbox.curselection()
        if sel:
            self._select(sel[0])

    def _restore_selection(self, _=None):
        """Called by <FocusOut>. Puts the highlight back if Tk cleared it."""
        self.listbox.selection_set(self._current_idx)

    def _show_algo(self, idx: int):
        """Update the right panel for the algorithm at position `idx`."""
        name = list(self.ALGOS.keys())[idx]
        cat, kind = self.ALGOS[name]

        self.algo_title.config(text=name)
        self.cat_badge.config(text=f"  {cat}  ")
        set_text(self.output_text, "")  # clear stale output

        # Hide all algorithm-specific blocks, then show the relevant one
        for f in (self.aes_frame, self.des_frame, self.tdes_frame, self.rsa_frame):
            f.pack_forget()

        if kind == "aes":
            self.aes_frame.pack(fill="x", pady=(0, 4))
            self._aes_sync_iv()         # apply IV row visibility for current mode
        elif kind == "des":
            self.des_frame.pack(fill="x", pady=(0, 4))
        elif kind == "3des":
            self.tdes_frame.pack(fill="x", pady=(0, 4))
            self._tdes_sync_iv()        # apply IV row visibility for current mode
        elif kind == "rsa":
            self.rsa_frame.pack(fill="x", pady=(0, 4))
            bits = 1024 if name == "RSA-1024" else 2048
            self._rsa_load(bits)        # restore cached key fields if available

        # Hide Decrypt button for one-way hash algorithms
        if kind == "hash":
            self.dec_btn.pack_forget()
        else:
            if not self.dec_btn.winfo_ismapped():
                self.dec_btn.pack(side="left")

        hints = {
            "Base64":      "Encodes binary data as ASCII text. Not encryption.",
            "Hex":         "Converts each byte to two hex digits.",
            "URL":         "Percent-encodes text for URLs. Supports Arabic and Unicode.",
            "SHA-256":     "One-way 256-bit hash. Cannot be reversed.",
            "SHA-512":     "One-way 512-bit hash. Cannot be reversed.",
            "Salted Hash": "SHA-256 + random 16-byte salt. Safe for passwords.",
            "AES":         "Select key size + mode. IV row adapts automatically.",
            "DES":         "Key = 8 bytes. IV = 8 bytes. Deprecated — use AES.",
            "3DES":        "Key = 16 or 24 bytes. IV = 8 bytes. ECB hides IV.",
            "RSA-1024":    "Paste Public / Private hex keys, or click Generate.",
            "RSA-2048":    "Paste Public / Private hex keys, or click Generate.",
        }
        self.hint_lbl.config(text=hints.get(name, ""))

    def _current_name(self) -> str:
        """Return the name string of the currently selected algorithm."""
        return list(self.ALGOS.keys())[self._current_idx]

    # ── AES helpers ───────────────────────────────────────────────────────────

    def _aes_sync_iv(self):
        """Show or hide the AES IV row, and update its label and hint text."""
        mode = self.aes_mode_var.get()
        if mode not in AES_MODE_IV:
            return
        needs_iv, lbl_text, iv_bytes, hint = AES_MODE_IV[mode]
        self.aes_mode_hint.config(text=hint)
        if needs_iv:
            self.aes_iv_lbl.config(text=lbl_text)
            self.aes_iv_row.pack(fill="x", pady=(0, 4))
        else:
            self.aes_iv_row.pack_forget()
            self.aes_iv_var.set("")     # clear stale value when hiding

    def _aes_gen_key(self):
        """Generate a random AES key matching the selected key size."""
        size = int(self.aes_ksz_var.get().split()[0])   # "16 bytes …" → 16
        self.aes_key_var.set(hex_encode(os.urandom(size)))

    def _aes_gen_iv(self):
        """Generate a random IV of the correct byte length for the current mode."""
        iv_bytes = AES_MODE_IV[self.aes_mode_var.get()][2]
        if iv_bytes > 0:
            self.aes_iv_var.set(hex_encode(os.urandom(iv_bytes)))

    def _aes_get_key(self) -> bytes:
        """Parse and validate the AES key hex field."""
        raw = self.aes_key_var.get().strip()
        if not raw:
            raise ValueError("AES key is empty. Click 'Gen Key'.")
        try:
            key = hex_decode(raw)
        except Exception:
            raise ValueError("AES key must be valid hex. Use 'Gen Key'.")
        if len(key) not in (16, 24, 32):
            raise ValueError(
                f"AES key must be 16, 24, or 32 bytes. Got {len(key)} bytes.\n"
                f"Select the correct size and regenerate.")
        return key

    def _aes_get_iv(self) -> bytes:
        """Parse the AES IV field; auto-generate a correct IV if the field is empty."""
        mode = self.aes_mode_var.get()
        needs_iv, _, iv_bytes, _ = AES_MODE_IV[mode]
        if not needs_iv:
            return None                 # ECB needs no IV
        raw = self.aes_iv_var.get().strip()
        if not raw:
            iv = os.urandom(iv_bytes)   # auto-generate
            self.aes_iv_var.set(hex_encode(iv))
            return iv
        try:
            iv = hex_decode(raw)
        except Exception:
            raise ValueError("AES IV must be valid hex. Use 'Gen IV'.")
        if len(iv) != iv_bytes:
            raise ValueError(
                f"Mode {mode} needs a {iv_bytes}-byte IV. Got {len(iv)} bytes.\n"
                f"Click 'Gen IV' to fix this.")
        return iv

    # ── 3DES helpers ──────────────────────────────────────────────────────────

    def _tdes_sync_iv(self):
        """Show or hide the 3DES IV row depending on the selected mode."""
        if self.tdes_mode_var.get() == "ECB":
            self.tdes_iv_row.pack_forget()
            self.tdes_iv_var.set("")
        else:
            if not self.tdes_iv_row.winfo_ismapped():
                self.tdes_iv_row.pack(fill="x", pady=(0, 4))

    def _tdes_gen_key(self):
        """Generate a 3DES key of the correct byte size (16 or 24)."""
        size = int(self.tdes_ksz_var.get().split()[0])  # "16 bytes …" → 16
        self.tdes_key_var.set(hex_encode(os.urandom(size)))

    def _tdes_get_key(self) -> bytes:
        """Parse and validate the 3DES key hex field."""
        raw = self.tdes_key_var.get().strip()
        if not raw:
            raise ValueError("3DES key is empty. Click 'Gen Key'.")
        try:
            key = hex_decode(raw)
        except Exception:
            raise ValueError("3DES key must be valid hex. Use 'Gen Key'.")
        if len(key) not in (16, 24):
            raise ValueError(f"3DES key must be 16 or 24 bytes. Got {len(key)} bytes.")
        return key

    def _tdes_get_iv(self) -> bytes:
        """Parse the 3DES IV field; auto-generate if empty."""
        raw = self.tdes_iv_var.get().strip()
        if not raw:
            iv = os.urandom(8)
            self.tdes_iv_var.set(hex_encode(iv))
            return iv
        try:
            iv = hex_decode(raw)
        except Exception:
            raise ValueError("3DES IV must be valid hex. Use 'Gen IV'.")
        if len(iv) != 8:
            raise ValueError(f"3DES IV must be 8 bytes. Got {len(iv)} bytes.")
        return iv

    # ── RSA helpers ───────────────────────────────────────────────────────────

    def _rsa_generate(self):
        """Generate a new RSA key pair and populate the Public/Private fields."""
        name = self._current_name()
        bits = 1024 if name == "RSA-1024" else 2048
        self.rsa_status.config(
            text=f"Generating {bits}-bit keys… please wait", fg=C["warn"])
        self.root.update()          # repaint before the blocking key-gen call
        try:
            rsa = RSA.generate(bits=bits)
            self._rsa_cache[bits] = rsa
            # rsa_pub_hex / rsa_priv_hex imported directly from crypto_lib
            self.rsa_pub_var.set(rsa_pub_hex(rsa))
            self.rsa_prv_var.set(rsa_priv_hex(rsa))
            self.rsa_status.config(
                text=f"Keys ready ({bits}-bit). Copy fields above to save them.",
                fg=C["ok"])
        except Exception as e:
            self.rsa_status.config(text="Generation failed.", fg=C["danger"])
            messagebox.showerror("RSA Error", str(e))

    def _rsa_load(self, bits: int):
        """Populate the key fields from cache if a pair for `bits` exists."""
        if bits in self._rsa_cache:
            rsa = self._rsa_cache[bits]
            self.rsa_pub_var.set(rsa_pub_hex(rsa))
            self.rsa_prv_var.set(rsa_priv_hex(rsa))
            self.rsa_status.config(text=f"Keys loaded ({bits}-bit).", fg=C["ok"])
        else:
            self.rsa_status.config(
                text="Paste your keys, or click 'Generate Key Pair'.",
                fg=C["muted"])

    def _rsa_get(self) -> RSA:
        """Build an RSA instance from whatever is in the Public/Private fields."""
        pub = self.rsa_pub_var.get().strip()
        prv = self.rsa_prv_var.get().strip()
        if not pub:
            raise ValueError(
                "Public Key field is empty.\n"
                "Paste a hex key or click 'Generate Key Pair'.")
        try:
            # rsa_from_hex imported from crypto_lib — no duplicate here
            return rsa_from_hex(pub, prv)
        except Exception as ex:
            raise ValueError(f"Could not parse RSA key:\n{ex}")

    # ── Reset ─────────────────────────────────────────────────────────────────

    def _reset(self):
        """Clear all key, IV, input, and output fields."""
        for v in (self.aes_key_var, self.aes_iv_var,
                  self.des_key_var, self.des_iv_var,
                  self.tdes_key_var, self.tdes_iv_var,
                  self.rsa_pub_var, self.rsa_prv_var):
            v.set("")
        set_text(self.input_text,  "")
        set_text(self.output_text, "")
        self.hint_lbl.config(text="")

    # ── Encrypt / Decrypt ─────────────────────────────────────────────────────

    def _do_encrypt(self):
        """Read input, run the selected algorithm, show result."""
        text = get_text(self.input_text).strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please type something in the Input box.")
            return
        try:
            set_text(self.output_text, self._run(text, encrypt=True))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _do_decrypt(self):
        """Read ciphertext, run the selected algorithm in reverse, show result."""
        text = get_text(self.input_text).strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please paste ciphertext in the Input box.")
            return
        try:
            set_text(self.output_text, self._run(text, encrypt=False))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _run(self, text: str, encrypt: bool) -> str:
        """Dispatch to the correct crypto_lib function for the selected algorithm."""
        name = self._current_name()

        # ── Encoding ──────────────────────────────────────────────────────────
        if name == "Base64":
            return (base64_encode(text.encode("utf-8")) if encrypt
                    else safe_decode(base64_decode(text)))

        if name == "Hex":
            return (hex_encode(text.encode("utf-8")) if encrypt
                    else safe_decode(hex_decode(text)))

        if name == "URL":
            return url_encode(text) if encrypt else url_decode(text)

        # ── Hashing (one-way — no decrypt path) ───────────────────────────────
        if name == "SHA-256":
            return sha256_hex(text.encode("utf-8"))

        if name == "SHA-512":
            return sha512_hex(text.encode("utf-8"))

        if name == "Salted Hash":
            r = salted_hash(text)
            return f"salt : {r['salt']}\nhash : {r['hash']}"

        # ── AES ───────────────────────────────────────────────────────────────
        if name == "AES":
            key  = self._aes_get_key()
            iv   = self._aes_get_iv()       # None for ECB
            mode = self.aes_mode_var.get()
            aes  = AES(key)
            if encrypt:
                result = aes.encrypt(text.encode("utf-8"), mode=mode, iv=iv)
                if isinstance(result, dict):     # GCM returns {ciphertext, tag, iv}
                    return (f"ciphertext : {result['ciphertext']}\n"
                            f"tag        : {result['tag']}\n"
                            f"iv         : {result['iv']}")
                return result                    # other modes: Base64 string
            else:
                return safe_decode(aes.decrypt(text, mode=mode, iv=iv))

        # ── DES ───────────────────────────────────────────────────────────────
        if name == "DES":
            raw = self.des_key_var.get().strip()
            if not raw:
                raise ValueError("DES key is empty. Click 'Gen Key'.")
            key  = hex_decode(raw)
            if len(key) != 8:
                raise ValueError(f"DES key must be 8 bytes. Got {len(key)}.")
            mode = self.des_mode_var.get()
            if mode == "ECB":
                iv = None
            else:
                raw_iv = self.des_iv_var.get().strip()
                if not raw_iv:
                    iv = os.urandom(8)
                    self.des_iv_var.set(hex_encode(iv))
                else:
                    iv = hex_decode(raw_iv)
                    if len(iv) != 8:
                        raise ValueError(f"DES IV must be 8 bytes. Got {len(iv)}.")
            des = DES(key)
            return (des.encrypt(text.encode("utf-8"), mode=mode, iv=iv) if encrypt
                    else safe_decode(des.decrypt(text, mode=mode, iv=iv)))

        # ── 3DES ──────────────────────────────────────────────────────────────
        if name == "3DES":
            key  = self._tdes_get_key()
            mode = self.tdes_mode_var.get()
            iv   = None if mode == "ECB" else self._tdes_get_iv()
            tdes = TripleDES(key)
            return (tdes.encrypt(text.encode("utf-8"), mode=mode, iv=iv) if encrypt
                    else safe_decode(tdes.decrypt(text, mode=mode, iv=iv)))

        # ── RSA ───────────────────────────────────────────────────────────────
        if name in ("RSA-1024", "RSA-2048"):
            rsa = self._rsa_get()
            if encrypt:
                return rsa.encrypt(text.encode("utf-8"))
            else:
                if rsa.d is None:
                    raise ValueError(
                        "Decryption requires the Private Key.\n"
                        "Fill the Private Key field or generate a fresh pair.")
                return safe_decode(rsa.decrypt(text))

        raise ValueError(f"Unknown algorithm: {name}")

    def _copy_out(self):
        """Copy the output text box content to the clipboard."""
        out = get_text(self.output_text).strip()
        if out:
            clip_copy(self.root, out, self.copy_out_btn)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    """Root window: dark theme, header bar, two-tab Notebook."""

    def __init__(self):
        super().__init__()
        self.title("Try Crypto Toolkit")
        self.geometry("820x780")        # initial size
        self.minsize(720, 640)          # minimum size when resized
        self.configure(bg=C["bg"])
        self._apply_style()
        self._build()

    def _apply_style(self):
        """Override ttk widget colours to match the dark theme."""
        s = ttk.Style(self)
        s.theme_use("clam")             # 'clam' allows the most colour overrides

        s.configure("TCombobox",
                    fieldbackground=C["input_bg"],
                    background=C["input_bg"],
                    foreground=C["text"],
                    selectbackground=C["accent"],
                    selectforeground=C["text"],
                    bordercolor=C["border"],
                    arrowcolor=C["text"])
        s.map("TCombobox",
              fieldbackground=[("readonly", C["input_bg"])],
              foreground=[("readonly", C["text"])])

        s.configure("TNotebook",
                    background=C["bg"], borderwidth=0, tabmargins=0)
        s.configure("TNotebook.Tab",
                    background=C["panel"], foreground=C["muted"],
                    padding=[16, 8], font=FB)
        s.map("TNotebook.Tab",
              background=[("selected", C["accent"])],
              foreground=[("selected", C["text"])])

    def _build(self):
        """Build the header bar and attach the two tabs."""
        # Header bar
        hdr = tk.Frame(self, bg=C["panel"], height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="   Try Crypto Toolkit",
                 font=("Consolas", 15, "bold"),
                 bg=C["panel"], fg=C["accent"],
                 ).pack(side="left", padx=16, pady=12)
        tk.Label(hdr, text="Powered by Azmygg Group",
                 font=FS, bg=C["panel"], fg=C["muted"],
                 ).pack(side="right", padx=16)

        # Two-tab Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        nb.add(HomePage(nb, self),     text="   Home — Passwords Security   ")
        nb.add(CryptoToolkit(nb, self), text="   Try Crypto Toolkit   ")


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    App().mainloop()