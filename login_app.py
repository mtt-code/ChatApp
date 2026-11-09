"""
CustomTkinter login / register screen (username + email) on top of auth.py.

pip install customtkinter sqlalchemy cryptography
Run:  python login_app.py   (keep it in the same folder as auth.py and users_aes.py)
"""
import customtkinter as ctk

from auth import EMAIL_RE, MIN_PASSWORD_LEN, USERNAME_RE, authenticate, register


# --- UI ------------------------------------------------------------------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Sign in")
        self.geometry("420x640")
        self.resizable(False, False)

        self.mode = "login"  # or "register"
        self.container = ctk.CTkFrame(self, corner_radius=16)
        self.container.pack(expand=True, fill="both", padx=30, pady=30)

        self.show_auth()

    # -- helpers --
    def clear(self):
        for child in self.container.winfo_children():
            child.destroy()

    def set_message(self, text: str, ok: bool = False):
        self.message.configure(text=text, text_color=("#2e8b57" if ok else "#e5484d"))

    def toggle_password(self):
        show = "" if self.show_pw.get() else "*"
        self.password_entry.configure(show=show)
        if self.mode == "register":
            self.confirm_entry.configure(show=show)

    def make_entry(self, placeholder: str, show: str = ""):
        entry = ctk.CTkEntry(
            self.container, placeholder_text=placeholder, show=show, width=280, height=40
        )
        entry.pack(pady=6)
        entry.bind("<Return>", lambda _e: self.submit())
        return entry

    # -- auth view (login + register) --
    def show_auth(self):
        self.clear()
        is_login = self.mode == "login"

        ctk.CTkLabel(
            self.container,
            text="Welcome back" if is_login else "Create account",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).pack(pady=(36, 4))
        ctk.CTkLabel(
            self.container,
            text="Sign in to continue" if is_login else "Fill in the details below",
            text_color="gray",
        ).pack(pady=(0, 20))

        if is_login:
            self.identifier_entry = self.make_entry("Username or email")
            first = self.identifier_entry
        else:
            self.username_entry = self.make_entry("Username (3-20: a-z, 0-9, _)")
            self.email_entry = self.make_entry("Email")
            first = self.username_entry

        self.password_entry = self.make_entry("Password", show="*")
        if not is_login:
            self.confirm_entry = self.make_entry("Confirm password", show="*")

        self.show_pw = ctk.CTkCheckBox(
            self.container, text="Show password", command=self.toggle_password
        )
        self.show_pw.pack(pady=(6, 2), anchor="w", padx=60)

        self.message = ctk.CTkLabel(self.container, text="", wraplength=280)
        self.message.pack(pady=(6, 0))

        ctk.CTkButton(
            self.container,
            text="Sign in" if is_login else "Create account",
            width=280, height=42,
            command=self.submit,
        ).pack(pady=(10, 8))

        ctk.CTkButton(
            self.container,
            text="No account? Register" if is_login else "Have an account? Sign in",
            width=280, fg_color="transparent",
            text_color=("gray20", "gray80"),
            hover_color=("gray85", "gray25"),
            command=self.switch_mode,
        ).pack()

        first.focus()

    def switch_mode(self):
        self.mode = "register" if self.mode == "login" else "login"
        self.show_auth()

    def submit(self):
        password = self.password_entry.get()

        if self.mode == "login":
            identifier = self.identifier_entry.get().strip()
            if not identifier or not password:
                return self.set_message("Enter your username/email and password.")
            result = authenticate(identifier, password)
            if result is None:
                return self.set_message("Invalid username/email or password.")
            self.show_home(*result)
            return

        # register
        username = self.username_entry.get().strip().lower()
        email = self.email_entry.get().strip()
        if not USERNAME_RE.match(username):
            return self.set_message(
                "Username must be 3-20 characters: letters, numbers or underscore."
            )
        if not EMAIL_RE.match(email):
            return self.set_message("Please enter a valid email address.")
        if len(password) < MIN_PASSWORD_LEN:
            return self.set_message(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        if password != self.confirm_entry.get():
            return self.set_message("Passwords do not match.")
        error = register(username, email, password)
        if error:
            return self.set_message(error)

        self.mode = "login"
        self.show_auth()
        self.set_message("Account created. You can sign in now.", ok=True)

    # -- logged-in view --
    def show_home(self, user_id: str, username: str, email: str):
        self.clear()
        ctk.CTkLabel(
            self.container, text=f"Hi, {username}!",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).pack(pady=(70, 10))
        ctk.CTkLabel(self.container, text=email, font=ctk.CTkFont(size=16)).pack()
        ctk.CTkLabel(
            self.container, text=f"User ID\n{user_id}", text_color="gray", wraplength=300
        ).pack(pady=20)
        ctk.CTkButton(
            self.container, text="Log out", width=280, height=42, command=self.logout
        ).pack(pady=20)

    def logout(self):
        self.mode = "login"
        self.show_auth()


if __name__ == "__main__":
    ctk.set_appearance_mode("system")   # "light" / "dark" / "system"
    ctk.set_default_color_theme("blue")
    App().mainloop()
