Aeon-f Firewall
================

Aeon-f is a Python-based firewall solution that provides a variety of features, including the ability to add, remove, list, monitor, log, and test firewall rules.

Table of Contents
-----------------
- Overview
- Installation
- Setting Up PYTHONPATH
    - What is PYTHONPATH?
    - How to Use PYTHONPATH
    - Verifying PYTHONPATH
- Usage
    - Running Aeon-f
    - Command List
    - Examples
- Troubleshooting

Overview
--------
Aeon-f allows you to manage your firewall rules and monitor activities through a simple command-line interface (CLI). The firewall can be customized with rules that define which traffic should be allowed or blocked.

Installation
------------
To install the Aeon-f firewall, follow these steps:

1. Clone or download the repository.
2. Navigate to the project directory:
    ```
    cd /path/to/aeon-f
    ```
3. Install the required dependencies:
    ```
    pip install -r requirements.txt
    ```

Setting Up PYTHONPATH
----------------------
### What is PYTHONPATH?
`PYTHONPATH` is an environment variable that Python uses to determine where to look for modules. When running Python programs, it checks directories listed in `PYTHONPATH` in addition to default locations (like the standard library).

### How to Use PYTHONPATH

#### Set PYTHONPATH Temporarily (for the current session):

- **Linux/macOS**:
    ```
    export PYTHONPATH="/path/to/your/project:/path/to/other/directory"
    python your_script.py
    ```
- **Windows (Command Prompt)**:
    ```
    set PYTHONPATH=C:\path\to\your\project;C:\path\to\other\directory
    python your_script.py
    ```
- **Windows (PowerShell)**:
    ```
    $env:PYTHONPATH="C:\path\to\your\project;C:\path\to\other\directory"
    python your_script.py
    ```

#### Set PYTHONPATH Permanently (to persist across sessions):

- **Linux/macOS**: Add the following line to your `.bashrc` or `.zshrc` file:
    ```
    export PYTHONPATH="/path/to/your/project:/path/to/other/directory"
    ```
    Then, run:
    ```
    source ~/.bashrc  # or ~/.zshrc for zsh
    ```

- **Windows**:
    1. Open the Start Menu and search for Environment Variables.
    2. Click on Edit the system environment variables.
    3. In the System Properties window, click Environment Variables.
    4. Under System Variables, click New and enter `PYTHONPATH` as the name, and the path to your project as the value.
    5. Click OK and restart any terminal windows for the changes to take effect.

#### Using sys.path in Your Script:
You can modify `sys.path` directly in your script to add directories to the search path for modules. Example:
    ```python
    import sys
    sys.path.append('/path/to/your/project')

    import your_module
    ```

### Verifying PYTHONPATH
To verify the directories included in `PYTHONPATH`, you can run the following code in Python:
    ```python
    import sys
    print(sys.path)
    ```
This will print out a list of directories where Python is currently searching for modules.

Usage
------
### Running Aeon-f
To use Aeon-f, run the following command in the terminal:
    ```
    python manage_firewall.py [command] [options]
    ```

### Command List
- `add`: Add a new rule
- `remove`: Remove an existing rule
- `list`: List all rules
- `monitor`: Monitor the firewall activity
- `log`: View the firewall logs
- `test`: Test firewall functionality

### Examples
- **Add a rule**:
    ```
    python manage_firewall.py add --src 192.168.1.1 --action ALLOW
    ```
    This adds a rule to allow traffic from 192.168.1.1.

- **Remove a rule**:
    ```
    python manage_firewall.py remove --src 192.168.1.1
    ```
    This removes the rule for 192.168.1.1.

- **List all rules**:
    ```
    python manage_firewall.py list
    ```
    This lists all the currently active firewall rules.

- **Monitor activity**:
    ```
    python manage_firewall.py monitor
    ```
    This monitors firewall activity in real-time.

- **View firewall logs**:
    ```
    python manage_firewall.py log
    ```
    This views the logs of the firewall.

- **Test firewall functionality**:
    ```
    python manage_firewall.py test
    ```
    This tests the firewall's functionality.

Troubleshooting
---------------
### ModuleNotFoundError
If you face an issue like `ModuleNotFoundError: No module named 'add_rule'`, make sure that your `PYTHONPATH` is correctly set to include the project's directory or the directories containing your Python modules.

To fix this:
1. Make sure `add_rule.py` is in the correct location.
2. Set `PYTHONPATH` correctly using one of the methods described in the "Setting Up PYTHONPATH" section.

### Firewall Not Functioning
If the firewall is not functioning as expected:
1. Verify that you have the correct permissions to modify firewall rules.
2. Ensure that the necessary dependencies are installed using:
    ```
    pip install -r requirements.txt
    ```
