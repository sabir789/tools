# GoExtGen: Intelligent File Extension Generator for Recon

GoExtGen is a lightweight and highly customizable Go-based command-line tool designed to supercharge your reconnaissance efforts during penetration testing. It takes keywords (from a file, direct input, or pipeline) and intelligently generates a comprehensive list of potential filenames by appending various common and custom extensions. This helps you uncover hidden or forgotten files and directories on target systems.

---

## ✨ Features

* **Flexible Input:** Accept single keywords, lists from a file, or directly from a pipeline (stdin).
* **Intelligent Keyword Extraction:** Automatically extracts relevant parts from file paths (e.g., `app/config` -> `app`, `config`) and domain names (e.g., `sub.domain.com` -> `sub`, `domain`).
* **Extensive Default Extensions:** Comes with a built-in list of common file extensions (`.sh`, `.zip`, `.json`, `.sql`, `.env`, `.bak`, etc.) relevant for exposing sensitive data or misconfigurations.
* **Customizable Extensions:** Easily add your own specific extensions to the generation process.
* **Pipeline Friendly:** Designed to seamlessly integrate with other command-line tools like `subfinder`, `anew`, `httpx`, and more.

---

## 🚀 Installation

To get started with GoExtGen, ensure you have Go installed on your Kali Linux (or any other compatible system).

1.  **Clone the repository (or save the code):**
    ```bash
    git clone [https://github.com/sabir789/goextgen.git](https://github.com/sabir789/goextgen.git)
    cd goextgen
    ```
2.  **Build the executable:**
    ```bash
    go build -o goextgen goextgen.go
    ```
    This command compiles the Go source code into a standalone executable named `goextgen`.
3.  **Make it executable:**
    ```bash
    chmod +x goextgen
    ```
    Now the `goextgen` binary is ready to run!

---

## 💡 Usage

GoExtGen is designed for simplicity and versatility.

```bash
./goextgen [OPTIONS]
