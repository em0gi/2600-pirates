#!/usr/bin/env python3
import tkinter as tk
from tkinter import Listbox, END, Menu, messagebox, ttk, scrolledtext
import irc.client
import queue
import threading
import socket
import ssl
import logging
from PIL import Image, ImageTk, ImageEnhance
import tkinter.colorchooser as colorchooser

# Set up logging to console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Global queues for thread communication
incoming_queue = queue.Queue()
send_queue = queue.Queue()
raw_send_queue = queue.Queue()
user_colors = {}
message_history = []
history_index = -1
current_column_count = 6

# Service-related globals
service_running = False
stop_event = None
server_thread = None
client_infos = []
client_queues_lock = threading.Lock()

# Hardcoded ZNC connection details
ZNC_SERVER = "<server ip>"
ZNC_PORT = <port>
IRC_NICKNAME = "<username>"
ZNC_USERNAME = "<username>"
NETWORK = "2600"
ZNC_PASSWORD = "<password>"
SERVER_IDENTIFIED_NICK = "<server side nick>"

# mIRC color mapping to Tkinter color names
mirc_colors = {
    '0': 'white', '1': 'black', '2': 'navy', '3': 'green', '4': 'red',
    '5': 'brown', '6': 'purple', '7': 'olive', '8': 'yellow', '9': 'lime',
    '10': 'darkcyan', '11': 'cyan', '12': 'skyblue', '13': 'fuchsia',
    '14': 'gray', '15': 'silver'
}

# Default color settings
default_bg_color = '#FFFFFF'  # White
default_fg_color = '#000000'  # Black

# Load colors from config.txt or create it with defaults
try:
    with open('config.txt', 'r') as f:
        for line in f:
            if line.startswith('background_color='):
                default_bg_color = line.strip().split('=')[1]
            elif line.startswith('text_color='):
                default_fg_color = line.strip().split('=')[1]
except FileNotFoundError:
    with open('config.txt', 'w') as f:
        f.write(f"background_color={default_bg_color}\n")
        f.write(f"text_color={default_fg_color}\n")

# Load dictionary for Wordel helper
try:
    with open('filtered-american-english.txt', 'r') as f:
        dictionary = [word.strip().lower() for word in f]
except FileNotFoundError:
    logger.error("Dictionary file 'filtered-american-english.txt' not found.")
    dictionary = []

### Helper Functions

def match_word(word_pattern, word, exclude_chars='', include_chars=''):
    if len(word_pattern) != len(word):
        return False
    for i, char in enumerate(word_pattern):
        if char != '-' and char != word[i]:
            return False
    if exclude_chars and any(char in word for char in exclude_chars):
        return False
    for char in include_chars:
        if char not in word:
            return False
    return True

def parse_mirc_message(message):
    segments = []
    current_text = ''
    state = {'fg': 'default', 'bold': False, 'underline': False}
    i = 0
    while i < len(message):
        char = message[i]
        if char == '\x03':  # Color code
            if current_text:
                segments.append((current_text, state.copy()))
                current_text = ''
            i += 1
            if i < len(message) and message[i].isdigit():
                fg = ''
                while i < len(message) and message[i].isdigit() and len(fg) < 2:
                    fg += message[i]
                    i += 1
                state['fg'] = fg
                if i < len(message) and message[i] == ',':
                    i += 1
                    while i < len(message) and message[i].isdigit():
                        i += 1
            else:
                state['fg'] = 'default'
        elif char == '\x02':  # Bold toggle
            if current_text:
                segments.append((current_text, state.copy()))
                current_text = ''
            state['bold'] = not state['bold']
            i += 1
        elif char == '\x1F':  # Underline toggle
            if current_text:
                segments.append((current_text, state.copy()))
                current_text = ''
            state['underline'] = not state['underline']
            i += 1
        elif char == '\x0F':  # Reset
            if current_text:
                segments.append((current_text, state.copy()))
                current_text = ''
            state = {'fg': 'default', 'bold': False, 'underline': False}
            i += 1
        else:
            current_text += char
            i += 1
    if current_text:
        segments.append((current_text, state.copy()))
    return segments

def load_commands():
    try:
        with open('commands.txt', 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        commands = {}
        current_tab = "General"
        commands[current_tab] = []
        for line in lines:
            if line.startswith('[') and line.endswith(']'):
                current_tab = line[1:-1]
                commands[current_tab] = []
            else:
                commands[current_tab].append(line)
    except FileNotFoundError:
        commands = {"General": []}
    try:
        with open('user_commands.txt', 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        user_commands = {}
        current_menu = "General"
        user_commands[current_menu] = []
        for line in lines:
            if line.startswith('[') and line.endswith(']'):
                current_menu = line[1:-1]
                user_commands[current_menu] = []
            else:
                user_commands[current_menu].append(line)
    except FileNotFoundError:
        user_commands = {"General": []}
    return commands, user_commands

def load_games():
    games_dict = {}
    try:
        with open('games.txt', 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        current_game = None
        for line in lines:
            if line.startswith('[') and line.endswith(']'):
                current_game = line[1:-1]
                games_dict[current_game] = []
            elif current_game and ',' in line:
                try:
                    button_title, recipient, message = line.split(',', 2)
                    games_dict[current_game].append((button_title.strip(), recipient.strip(), message.strip()))
                except ValueError:
                    logger.warning(f"Invalid line in games.txt under [{current_game}]: {line}")
    except FileNotFoundError:
        logger.warning("games.txt not found, no games loaded.")
    return games_dict

def open_game_window(game_name, actions):
    game_window = tk.Toplevel(root)
    game_window.title(game_name)
    game_window.geometry("300x200")
    tk.Label(game_window, text=f"{game_name} Options", font=("Arial", 12, "bold")).pack(pady=10)
    for button_title, recipient, message in actions:
        btn = tk.Button(game_window, text=button_title,
                        command=lambda r=recipient, m=message: send_private_message(r, m))
        btn.pack(pady=5, padx=10, fill='x')

def send_private_message(recipient, message):
    send_queue.put(f"PRIVMSG {recipient} :{message}")
    logger.info(f"Queued private message to {recipient}: {message}")

def open_wordel_window():
    wordel_window = tk.Toplevel(root)
    wordel_window.title("Wordel Helper")
    wordel_window.geometry("400x300")
    tk.Label(wordel_window, text="Matching Words").pack(pady=(5, 0))
    output_area = tk.Text(wordel_window, wrap='word', height=10, state='disabled')
    output_area.pack(pady=5, padx=5, fill='both', expand=True)
    fields_frame = tk.Frame(wordel_window)
    fields_frame.pack(pady=5, padx=5, fill='x')
    tk.Label(fields_frame, text="Correct Parts (e.g., -a--e)").pack(side='left', padx=(0, 2))
    correct_parts = tk.Entry(fields_frame)
    correct_parts.pack(side='left', padx=2, fill='x', expand=True)
    tk.Label(fields_frame, text="Bad Letters (e.g., xy)").pack(side='left', padx=(0, 2))
    bad_letters = tk.Entry(fields_frame)
    bad_letters.pack(side='left', padx=2, fill='x', expand=True)
    tk.Label(fields_frame, text="Good Letters (e.g., bc)").pack(side='left', padx=(0, 2))
    good_letters = tk.Entry(fields_frame)
    good_letters.pack(side='left', padx=2, fill='x', expand=True)
    def search_wordel():
        pattern = correct_parts.get().lower().strip()
        exclude = bad_letters.get().lower().strip()
        include = good_letters.get().lower().strip()
        if not pattern:
            output_area.config(state='normal')
            output_area.delete('1.0', END)
            output_area.insert(END, "Please enter a pattern (e.g., -a--e).")
            output_area.config(state='disabled')
            return
        matching_words = [word for word in dictionary if match_word(pattern, word, exclude, include)]
        matching_words.sort()
        output_area.config(state='normal')
        output_area.delete('1.0', END)
        if matching_words:
            output_area.insert(END, "\n".join(matching_words))
        else:
            output_area.insert(END, "No matches found.")
        output_area.config(state='disabled')
    search_btn = tk.Button(wordel_window, text="Search", command=search_wordel)
    search_btn.pack(pady=5)

def toggle_service(port_entry, status_label, toggle_button):
    global service_running, stop_event, server_thread
    if service_running:
        stop_event.set()
        server_thread.join()
        service_running = False
    else:
        try:
            port = int(port_entry.get())
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid port number.")
            return
        stop_event = threading.Event()
        server_thread = threading.Thread(target=run_service, args=(port, stop_event))
        server_thread.daemon = True
        service_running = True
        server_thread.start()
    if service_running:
        status_label.config(text="Service is running.")
        toggle_button.config(text="Stop Service")
        port_entry.config(state='disabled')
    else:
        status_label.config(text="Service is stopped.")
        toggle_button.config(text="Start Service")
        port_entry.config(state='normal')

def open_service_window():
    global service_window
    if 'service_window' in globals() and service_window.winfo_exists():
        service_window.lift()
        return
    service_window = tk.Toplevel(root)
    service_window.title("Service Settings")
    tk.Label(service_window, text="Port:").grid(row=0, column=0)
    port_entry = tk.Entry(service_window)
    port_entry.insert(0, "1337")
    port_entry.grid(row=0, column=1)
    status_label = tk.Label(service_window, text="Service is stopped.")
    status_label.grid(row=1, column=0, columnspan=2)
    toggle_button = tk.Button(service_window, text="Start Service", command=lambda: toggle_service(port_entry, status_label, toggle_button))
    toggle_button.grid(row=2, column=0, columnspan=2)
    def update_ui():
        if service_running:
            status_label.config(text="Service is running.")
            toggle_button.config(text="Stop Service")
            port_entry.config(state='disabled')
        else:
            status_label.config(text="Service is stopped.")
            toggle_button.config(text="Start Service")
            port_entry.config(state='normal')
    update_ui()
    service_window.protocol("WM_DELETE_WINDOW", service_window.destroy)

def set_default_colors():
    """Open a window to set default background and foreground colors."""
    # Create the color selection window
    color_window = tk.Toplevel(root)
    color_window.title("Default Colors")
    color_window.geometry("400x400")
    color_window.resizable(False, False)  # Prevent resizing for consistent layout

    # Temporary variables to hold color selections until confirmed
    temp_bg_color = default_bg_color
    temp_fg_color = default_fg_color

    # Background Color section
    bg_label = tk.Label(color_window, text="Background Color")
    bg_label.grid(row=0, column=0, padx=10, pady=10)

    bg_frame = tk.Frame(color_window, width=50, height=50, bg=temp_bg_color, borderwidth=2, relief="solid")
    bg_frame.grid(row=0, column=1, padx=10, pady=10)

    def change_bg_color(event):
        nonlocal temp_bg_color
        new_color = colorchooser.askcolor(initialcolor=temp_bg_color)
        if new_color[1]:  # Check if a color was selected (not cancelled)
            temp_bg_color = new_color[1]
            bg_frame.config(bg=temp_bg_color)

    bg_frame.bind("<Button-1>", change_bg_color)

    # Foreground Color section
    fg_label = tk.Label(color_window, text="Foreground Color")
    fg_label.grid(row=1, column=0, padx=10, pady=10)

    fg_frame = tk.Frame(color_window, width=50, height=50, bg=temp_fg_color, borderwidth=2, relief="solid")
    fg_frame.grid(row=1, column=1, padx=10, pady=10)

    def change_fg_color(event):
        nonlocal temp_fg_color
        new_color = colorchooser.askcolor(initialcolor=temp_fg_color)
        if new_color[1]:  # Check if a color was selected (not cancelled)
            temp_fg_color = new_color[1]
            fg_frame.config(bg=temp_fg_color)

    fg_frame.bind("<Button-1>", change_fg_color)

    # Button functions
    def on_ok():
        global default_bg_color, default_fg_color
        default_bg_color = temp_bg_color  # Update global variables
        default_fg_color = temp_fg_color
        with open('config.txt', 'w') as f:  # Save to config file
            f.write(f"background_color={default_bg_color}\n")
            f.write(f"text_color={default_fg_color}\n")
        color_window.destroy()  # Close the window

    def on_cancel():
        color_window.destroy()  # Close without saving

    # Buttons
    cancel_button = tk.Button(color_window, text="Cancel", command=on_cancel)
    cancel_button.grid(row=2, column=0, pady=20)

    ok_button = tk.Button(color_window, text="OK", command=on_ok)
    ok_button.grid(row=2, column=1, pady=20)

    # Center the content horizontally
    color_window.grid_columnconfigure(0, weight=1)
    color_window.grid_columnconfigure(1, weight=1)

### IRC Client Class

class MyIRCClient(irc.client.SimpleIRCClient):
    def __init__(self, nickname, znc_username, network, znc_password):
        irc.client.SimpleIRCClient.__init__(self)
        self.nickname = nickname
        self.znc_username = znc_username
        self.network = network
        self.znc_password = znc_password
        self.user_list = []
        self.authenticated = False

    def on_all_raw_messages(self, connection, event):
        raw_message = event.arguments[0] if event.arguments else "<no args>"
        full_message = f"{event.type} {raw_message}"
        logger.info(f"Received: {full_message}")
        with client_queues_lock:
            for _, client_queue in client_infos:
                client_queue.put(raw_message)
        if ":irc.znc.in 464" in full_message and "Password required" in raw_message:
            auth_string = f"PASS {self.znc_username}/{self.network}:{self.znc_password}"
            connection.send_raw(auth_string)
            logger.info(f"Sent: {auth_string.strip()}")
            self.authenticated = True
            logger.info("Received 464 (Password required), sent /quote PASS command")
        elif "NOTICE" in full_message and ":" in raw_message:
            if raw_message.startswith(":"):
                sender_rest = raw_message[1:].split(" ", 2)
                if len(sender_rest) >= 3 and sender_rest[1] == "NOTICE":
                    nick = sender_rest[0].split("!", 1)[0]
                    message_part = sender_rest[2].split(":", 1)
                    if len(message_part) > 1:
                        message_body = message_part[1].strip()
                        body_parts = message_body.split(" ", 2)
                        if (len(body_parts) >= 3 and
                            body_parts[0].replace(",", "").isdigit() and
                            body_parts[1].startswith("[") and body_parts[1].endswith("]")):
                            message = body_parts[2]
                        else:
                            message = message_body
                        incoming_queue.put({'type': 'message', 'user': nick, 'text': message})
                        logger.info(f"User notice from {nick}: {message}")

    def on_welcome(self, connection, event):
        if self.authenticated:
            incoming_queue.put({'type': 'status', 'text': 'Connected'})
            connection.join('#pirates')
            logger.info("Sent: JOIN #pirates")
            logger.info("Connected to ZNC and joining #pirates")

    def on_disconnect(self, connection, event):
        incoming_queue.put({'type': 'status', 'text': 'Disconnected'})
        logger.info("Disconnected from ZNC")

    def on_join(self, connection, event):
        if event.target == '#pirates':
            nick = event.source.nick
            if not any(u['nick'] == nick for u in self.user_list):
                self.user_list.append({'nick': nick, 'op': False, 'voiced': False, 'away': False})
                incoming_queue.put({'type': 'join', 'user': nick})
                incoming_queue.put({'type': 'userlist', 'users': self.user_list})
                logger.info(f"User joined #pirates: {nick}")

    def on_part(self, connection, event):
        if event.target == '#pirates':
            nick = event.source.nick
            self.user_list = [u for u in self.user_list if u['nick'] != nick]
            incoming_queue.put({'type': 'part', 'user': nick})
            incoming_queue.put({'type': 'userlist', 'users': self.user_list})
            logger.info(f"User parted #pirates: {nick}")

    def on_quit(self, connection, event):
        nick = event.source.nick
        self.user_list = [u for u in self.user_list if u['nick'] != nick]
        incoming_queue.put({'type': 'quit', 'user': nick})
        incoming_queue.put({'type': 'userlist', 'users': self.user_list})
        logger.info(f"User quit: {nick}")

    def on_pubmsg(self, connection, event):
        if event.target == '#pirates':
            nick = event.source.nick
            message = event.arguments[0]
            incoming_queue.put({'type': 'message', 'user': nick, 'text': message})
            logger.info(f"Public message in #pirates from {nick}: {message}")

    def on_privmsg(self, connection, event):
        nick = event.source.nick
        message = event.arguments[0]
        incoming_queue.put({'type': 'private_message', 'user': nick, 'text': message})
        logger.info(f"Private message from {nick}: {message}")

    def on_namreply(self, connection, event):
        if event.arguments[1] == '#pirates':
            self.user_list.clear()
            for nick in event.arguments[2].split():
                is_op = nick.startswith('@')
                is_voiced = nick.startswith('+')
                clean_nick = nick.lstrip('@+')
                self.user_list.append({
                    'nick': clean_nick,
                    'op': is_op,
                    'voiced': is_voiced and not is_op,
                    'away': False
                })
            logger.info(f"Received user list for #pirates: {[u['nick'] for u in self.user_list]}")

    def on_endofnames(self, connection, event):
        if event.arguments[1] == '#pirates':
            incoming_queue.put({'type': 'userlist', 'users': self.user_list})
            logger.info("Finished receiving user list for #pirates")

    def on_mode(self, connection, event):
        if event.target == '#pirates':
            modes = event.arguments[0]
            affected_nicks = event.arguments[1:]
            for i, nick in enumerate(affected_nicks):
                user = next((u for u in self.user_list if u['nick'] == nick), None)
                if user:
                    if '+o' in modes:
                        user['op'] = True
                        user['voiced'] = False
                    elif '-o' in modes:
                        user['op'] = False
                    elif '+v' in modes:
                        user['voiced'] = True
                    elif '-v' in modes:
                        user['voiced'] = False
            incoming_queue.put({'type': 'userlist', 'users': self.user_list})
            logger.info(f"Mode change in #pirates: {modes} {affected_nicks}")

    def on_away(self, connection, event):
        nick = event.source.nick
        user = next((u for u in self.user_list if u['nick'] == nick), None)
        if user:
            user['away'] = True
            incoming_queue.put({'type': 'userlist', 'users': self.user_list})
            logger.info(f"User marked as away: {nick}")

    def on_back(self, connection, event):
        nick = event.source.nick
        user = next((u for u in self.user_list if u['nick'] == nick), None)
        if user:
            user['away'] = False
            incoming_queue.put({'type': 'userlist', 'users': self.user_list})
            logger.info(f"User returned from away: {nick}")

### Thread Functions

def irc_thread_func():
    incoming_queue.put({'type': 'status', 'text': 'Connecting...'})
    logger.info(f"Attempting to connect to {ZNC_SERVER}:{ZNC_PORT}")
    client = MyIRCClient(IRC_NICKNAME, ZNC_USERNAME, NETWORK, ZNC_PASSWORD)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_socket = context.wrap_socket(raw_socket, server_hostname=ZNC_SERVER)
        ssl_socket.connect((ZNC_SERVER, ZNC_PORT))
        client.connect(ZNC_SERVER, ZNC_PORT, IRC_NICKNAME, connect_factory=lambda x: ssl_socket)
        logger.info(f"Sent: NICK {IRC_NICKNAME}")
        logger.info(f"Sent: USER {IRC_NICKNAME} 0 * :{IRC_NICKNAME}")
    except Exception as e:
        incoming_queue.put({'type': 'status', 'text': f'Connection failed: {str(e)}'})
        logger.error(f"Connection failed: {str(e)}")
        return
    reactor = client.reactor
    while True:
        reactor.process_once(timeout=0.1)
        while not send_queue.empty():
            message = send_queue.get()
            if message.startswith("PRIVMSG "):
                client.connection.send_raw(message)
            else:
                client.connection.privmsg('#pirates', message)
                add_message_to_frame(SERVER_IDENTIFIED_NICK, message, 'message')
            logger.info(f"Sent: {message}")

        while not raw_send_queue.empty():
            raw_command = raw_send_queue.get()
            client.connection.send_raw(raw_command)
            logger.info(f"Sent raw: {raw_command}")

def run_service(port, stop_event):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.settimeout(1.0)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        logger.info(f"Service listening on port {port}")
        while not stop_event.is_set():
            try:
                client_socket, addr = server_socket.accept()
                client_socket.settimeout(1.0)
                client_queue = queue.Queue()
                with client_queues_lock:
                    client_infos.append((client_socket, client_queue))
                reader_thread = threading.Thread(target=client_reader, args=(client_socket, raw_send_queue, stop_event, client_infos))
                writer_thread = threading.Thread(target=client_writer, args=(client_socket, client_queue, stop_event, client_infos))
                reader_thread.daemon = True
                writer_thread.daemon = True
                reader_thread.start()
                writer_thread.start()
                logger.info(f"Client connected: {addr}")
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error in service: {e}")
                break
    except Exception as e:
        logger.error(f"Failed to start service: {e}")
    finally:
        server_socket.close()
        with client_queues_lock:
            for client_socket, _ in client_infos:
                try:
                    client_socket.close()
                except:
                    pass
            client_infos.clear()
        logger.info("Service stopped")

def client_reader(client_socket, raw_send_queue, stop_event, client_infos):
    try:
        while not stop_event.is_set():
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                command = data.decode('utf-8', errors='ignore').strip()
                if command:
                    raw_send_queue.put(command)
            except socket.timeout:
                continue
            except Exception as e:
                break
    finally:
        with client_queues_lock:
            for i, (cs, cq) in enumerate(client_infos):
                if cs == client_socket:
                    del client_infos[i]
                    break
        client_socket.close()

def client_writer(client_socket, client_queue, stop_event, client_infos):
    try:
        while not stop_event.is_set():
            try:
                message = client_queue.get(timeout=1.0)
                client_socket.send(message.encode('utf-8'))
            except queue.Empty:
                continue
            except Exception as e:
                break
    finally:
        with client_queues_lock:
            for i, (cs, cq) in enumerate(client_infos):
                if cs == client_socket:
                    del client_infos[i]
                    break
        client_socket.close()

### GUI Event Handlers

def send_message(event=None):
    global history_index
    message = entry.get()
    if message:
        send_queue.put(message)
        message_history.append(message)
        if len(message_history) > 100:
            message_history.pop(0)
            if history_index > 0:
                history_index -= 1
            elif history_index == 0:
                history_index = -1
        entry.delete(0, END)
        history_index = -1

def navigate_history(direction):
    global history_index
    if direction == 'up':
        if history_index == -1 and message_history:
            history_index = len(message_history) - 1
        elif history_index > 0:
            history_index -= 1
        else:
            return
    elif direction == 'down':
        if history_index != -1:
            if history_index < len(message_history) - 1:
                history_index += 1
            else:
                history_index = -1
                entry.delete(0, END)
                return
        else:
            return
    if history_index != -1:
        entry.delete(0, END)
        entry.insert(0, message_history[history_index])

def refresh_commands():
    global all_commands, current_user_commands
    commands, user_commands = load_commands()
    all_commands = commands
    current_user_commands = user_commands
    create_command_tabs(current_column_count)
    update_commands_menu()
    logger.info("Refreshed command tabs and user commands")

def set_column_count(count):
    global current_column_count
    current_column_count = count
    create_command_tabs(count)

def create_command_tabs(column_count):
    for widget in cmd_frame.winfo_children():
        widget.destroy()
    notebook = ttk.Notebook(cmd_frame)
    notebook.pack(fill='both', expand=True)
    for tab_name, cmd_list in all_commands.items():
        tab = tk.Frame(notebook)
        notebook.add(tab, text=tab_name)
        for i, cmd in enumerate(cmd_list):
            row = i // column_count
            col = i % column_count
            btn = tk.Button(tab, text=cmd, command=lambda c=cmd: send_queue.put(c))
            btn.grid(row=row, column=col, sticky='ew', padx=2, pady=2)
        for c in range(column_count):
            tab.grid_columnconfigure(c, weight=1)

def update_commands_menu():
    commands_menu.delete(0, 'end')
    for tab_name, cmd_list in all_commands.items():
        sub_menu = tk.Menu(commands_menu, tearoff=0)
        commands_menu.add_cascade(label=tab_name, menu=sub_menu)
        for cmd in cmd_list:
            sub_menu.add_command(label=cmd, command=lambda c=cmd: send_queue.put(c))

def on_right_click(event):
    try:
        # Get the selected user from the list
        index = user_list.nearest(event.y)
        user_list.selection_clear(0, END)
        user_list.selection_set(index)
        selection = user_list.get(index)

        # Extract the nickname (removing emojis or extra text)
        emojis = ['👑', '🎙️', '👤', '🌙']
        for emoji in emojis:
            if selection.startswith(emoji):
                temp = selection[len(emoji):]
                if ' •' in temp:
                    nickname = temp.split(' •')[0]
                else:
                    nickname = temp
                break
        else:
            nickname = selection

        # Create the right-click menu
        menu = tk.Menu(root, tearoff=0)

        # Add user commands from user-commands.txt
        for menu_name, cmd_list in current_user_commands.items():
            sub_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label=menu_name, menu=sub_menu)
            for cmd in cmd_list:
                formatted_cmd = cmd.replace('<user>', nickname)
                sub_menu.add_command(label=formatted_cmd, command=lambda c=formatted_cmd: send_queue.put(c))

        # Add a separator for clarity
        menu.add_separator()

        # Add the static options
        menu.add_command(label="Private Chat", command=lambda: open_private_chat(nickname))
        menu.add_command(label="Background Color", command=lambda: customize_user_bg_color(nickname))
        menu.add_command(label="Text Color", command=lambda: customize_user_fg_color(nickname))

        # Show the menu
        menu.post(event.x_root, event.y_root)
    except Exception as e:
        print(f"Error in right-click menu: {e}")

def load_user_colors():
    user_colors = {}
    try:
        with open('colors.txt', 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 2:  # Old format: nick, bg_color
                    username, bg_color = parts
                    user_colors[username] = {'bg': bg_color, 'fg': default_fg_color}  # Default text color
                elif len(parts) == 3:  # New format: nick, bg_color, fg_color
                    username, bg_color, fg_color = parts
                    user_colors[username] = {'bg': bg_color, 'fg': fg_color}
    except FileNotFoundError:
        pass  # File doesn’t exist yet, start with empty dict
    return user_colors

def save_user_colors():
    with open('colors.txt', 'w') as f:
        for username, colors in user_colors.items():
            bg_color = colors.get('bg', default_bg_color)  # Default if not set
            fg_color = colors.get('fg', default_fg_color)  # Default if not set
            f.write(f"{username},{bg_color},{fg_color}\n")

def customize_user_bg_color(username):
    color = colorchooser.askcolor(title=f"Choose background color for {username}")
    if color:  # Returns (RGB, hex_color) or None if canceled
        hex_color = color[1]
        if username not in user_colors:
            user_colors[username] = {}
        user_colors[username]['bg'] = hex_color
        save_user_colors()

def customize_user_fg_color(username):
    color = colorchooser.askcolor(title=f"Choose text color for {username}")
    if color:
        hex_color = color[1]
        if username not in user_colors:
            user_colors[username] = {}
        user_colors[username]['fg'] = hex_color
        save_user_colors()

def add_message_to_frame(username, text, msg_type='message'):
    global inner_frame, canvas, user_colors, mirc_colors
    username_width = 20
    if msg_type == 'message':
        colors = user_colors.get(username, {})
        bg_color = colors.get('bg', default_bg_color)
        fg_color = colors.get('fg', default_fg_color)
    else:
        bg_color = default_bg_color
        fg_color = default_fg_color
    msg_text = tk.Text(
        inner_frame,
        wrap='word',
        bg=bg_color,
        fg=fg_color,
        font=('Courier', 10),
        height=1,
        state='normal',
        borderwidth=0,
        highlightthickness=0,
        relief='flat'
    )
    msg_text.pack(fill='x', padx=5, pady=2)
    if msg_type == 'message':
        msg_text.tag_configure('bold', font=('Courier', 10, 'bold'))
        padding = ' ' * (username_width - len(username)) if len(username) <= username_width else ''
        msg_text.insert('end', padding + username + '   ', 'bold')
        segments = parse_mirc_message(text)
        for segment_text, state in segments:
            tag_name = f"fg{state['fg']}_b{state['bold']}_u{state['underline']}"
            if tag_name not in msg_text.tag_names():
                options = {}
                if state['fg'] != 'default':
                    options['foreground'] = mirc_colors.get(state['fg'], 'black')
                if state['bold']:
                    options['font'] = ('Courier', 10, 'bold')
                if state['underline']:
                    options['underline'] = True
                msg_text.tag_configure(tag_name, **options)
            msg_text.insert('end', segment_text, tag_name)
    else:
        if msg_type == 'status':
            full_text = f"{' ':>{username_width}}   *** {text}"
        elif msg_type == 'notification':
            full_text = f"{' ':>{username_width}}   notification: <{username}> {text}"
        elif msg_type == 'join':
            full_text = f"{' ':>{username_width}}   --> {username} has joined"
        elif msg_type == 'part':
            full_text = f"{' ':>{username_width}}   <-- {username} has left"
        elif msg_type == 'quit':
            full_text = f"{' ':>{username_width}}   <-- {username} has quit"
        else:
            full_text = text
        msg_text.insert('end', full_text)
    msg_text.config(state='disabled')
    canvas.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))
    canvas.yview_moveto(1.0)

def update_gui():
    while not incoming_queue.empty():
        event = incoming_queue.get()
        if event['type'] == 'private_message':
            user = event['user']
            text = event['text']
            if user in private_chat_windows:
                private_chat_windows[user].add_message(user, text, "contact")
            else:
                add_message_to_frame(user, f"(PM) {text}", 'message')
        elif event['type'] in ['message', 'status', 'notification', 'join', 'part', 'quit']:
            add_message_to_frame(event.get('user', ''), event.get('text', ''), event['type'])
        elif event['type'] == 'userlist':
            user_list.delete(0, 'end')
            for user in event['users']:
                display = (
                    f"👑{user['nick']} •" if user['op'] else
                    f"🎙️{user['nick']} •" if user['voiced'] else
                    f"🌙{user['nick']} •" if user['away'] else
                    f"👤{user['nick']}"
                )
                user_list.insert('end', display)
    root.after(100, update_gui)

def add_command_to_tab(tab_name, new_command):
    try:
        with open('commands.txt', 'r') as f:
            lines = f.readlines()
        insert_index = None
        for i, line in enumerate(lines):
            if line.strip().startswith('[') and line.strip().endswith(']'):
                current_tab = line.strip()[1:-1]
                if current_tab == tab_name:
                    for j in range(i + 1, len(lines)):
                        if lines[j].strip().startswith('[') and lines[j].strip().endswith(']'):
                            insert_index = j
                            break
                    else:
                        insert_index = len(lines)
                    break
        if insert_index is not None:
            lines.insert(insert_index, new_command + '\n')
            with open('commands.txt', 'w') as f:
                f.writelines(lines)
            return True
        else:
            return False
    except Exception as e:
        messagebox.showerror("Error", f"Failed to write to commands.txt: {str(e)}")
        return False

def add_item_to_tab(tab_name):
    new_command = entry.get().strip()
    if new_command:
        if add_command_to_tab(tab_name, new_command):
            refresh_commands()
        else:
            messagebox.showerror("Error", f"Tab '{tab_name}' not found in commands.txt")
    else:
        messagebox.showwarning("Warning", "No text in entry field to add.")

def on_entry_right_click(event):
    menu = tk.Menu(root, tearoff=0)
    for tab_name in all_commands.keys():
        sub_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label=tab_name, menu=sub_menu)
        sub_menu.add_command(label="Add item", command=lambda tn=tab_name: add_item_to_tab(tn))
    menu.post(event.x_root, event.y_root)

class PrivateChatWindow(tk.Toplevel):
    def __init__(self, parent, nickname):
        tk.Toplevel.__init__(self, parent)
        self.nickname = nickname
        self.title(f"Chat with {nickname}")
        self.geometry("400x600")
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        contact_frame = tk.Frame(self, bg="#ADD8E6")
        tk.Label(contact_frame, text=nickname, font=("Arial", 12, "bold"), bg="#ADD8E6").pack(padx=5, pady=5)
        contact_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        tk.Frame(self, height=2, bd=1, relief=tk.SUNKEN, bg="gray").grid(row=1, column=0, sticky="ew")
        self.chat_history = scrolledtext.ScrolledText(self, height=20, width=50, wrap=tk.WORD, borderwidth=2, relief=tk.SUNKEN, bg="white", font=("Arial", 10))
        self.chat_history.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        self.chat_history.tag_configure("contact", foreground="blue")
        self.chat_history.tag_configure("user", foreground="black")
        self.chat_history.config(state=tk.DISABLED)
        tk.Frame(self, height=2, bd=1, relief=tk.SUNKEN, bg="gray").grid(row=3, column=0, sticky="ew")
        bottom_frame = tk.Frame(self, bg="#F0F0F0")
        bottom_frame.grid(row=4, column=0, sticky="ew", padx=5, pady=5)
        self.input_text = tk.Text(bottom_frame, height=3, width=40, borderwidth=2, relief=tk.SUNKEN, font=("Arial", 10), bg="white")
        self.input_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=(0, 5))
        self.input_text.focus_set()
        tk.Button(custom_frame, text="Send", font=("Arial", 10), bg="#D3D3D3", command=self.send_message).pack(side=tk.RIGHT)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def send_message(self):
        message = self.input_text.get("1.0", tk.END).strip()
        if message:
            send_queue.put(f"PRIVMSG {self.nickname} :{message}")
            self.add_message("You", message, "user")
            self.input_text.delete("1.0", tk.END)

    def add_message(self, sender, message, tag):
        self.chat_history.config(state=tk.NORMAL)
        self.chat_history.insert(tk.END, f"{sender}: {message}\n", tag)
        self.chat_history.config(state=tk.DISABLED)
        self.chat_history.see(tk.END)

    def on_close(self):
        if self.nickname in private_chat_windows:
            del private_chat_windows[self.nickname]
        self.destroy()

def open_private_chat(nickname):
    if nickname in private_chat_windows:
        private_chat_windows[nickname].lift()
    else:
        window = PrivateChatWindow(root, nickname)
        private_chat_windows[nickname] = window

### Main Execution

if __name__ == '__main__':
    root = tk.Tk()
    root.title("2600 Pirates IRC")

    # Create menubar
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    # File menu
    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Refresh Commands", command=refresh_commands)
    column_menu = tk.Menu(file_menu, tearoff=0)
    file_menu.add_cascade(label="Column Count", menu=column_menu)
    column_menu.add_command(label="3", command=lambda: set_column_count(3))
    column_menu.add_command(label="4", command=lambda: set_column_count(4))
    column_menu.add_command(label="5", command=lambda: set_column_count(5))
    column_menu.add_command(label="6", command=lambda: set_column_count(6))
    file_menu.add_command(label="Default Colors", command=set_default_colors)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)

    # Interactive Games menu
    games_dict = load_games()
    games_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Interactive Games", menu=games_menu)
    for game_name, actions in games_dict.items():
        games_menu.add_command(label=game_name, command=lambda gn=game_name, acts=actions: open_game_window(gn, acts))

    # Commands menu
    commands_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Commands", menu=commands_menu)

    # Helpers menu
    helpers_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Helpers", menu=helpers_menu)
    helpers_menu.add_command(label="Wordel", command=open_wordel_window)
    helpers_menu.add_command(label="Service", command=open_service_window)

    # Load initial commands
    commands, user_commands = load_commands()
    all_commands = commands
    current_user_commands = user_commands
    update_commands_menu()

    # Load user colors
    user_colors = load_user_colors()

    # GUI layout with background image
    left_frame = tk.Frame(root)
    left_frame.grid(row=0, column=0, sticky='nsew')
    try:
        original_image = Image.open("pirate.jpg")
        resized_image = original_image.resize((200, 400), Image.Resampling.LANCZOS)
        white_bg = Image.new("RGBA", resized_image.size, (255, 255, 255, 255))
        enhancer = ImageEnhance.Brightness(resized_image.convert("RGBA"))
        transparent_image = Image.blend(white_bg, resized_image.convert("RGBA"), 0.2)
        bg_image = ImageTk.PhotoImage(transparent_image)
        bg_label = tk.Label(left_frame, image=bg_image)
        bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        bg_label.image = bg_image
    except FileNotFoundError:
        logger.error("Background image 'pirate.jpg' not found.")
    except Exception as e:
        logger.error(f"Error loading background image: {str(e)}")

    # Widgets inside left_frame using grid
    cmd_frame = tk.Frame(left_frame)
    cmd_frame.grid(row=0, column=0, sticky='nsew')

    # Message area with canvas and scrollbar
    message_frame = tk.Frame(left_frame)
    message_frame.grid(row=1, column=0, sticky='nsew')
    canvas = tk.Canvas(message_frame)
    scrollbar = tk.Scrollbar(message_frame, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    inner_frame = tk.Frame(canvas)
    inner_frame.config(bg=default_bg_color)
    canvas.create_window((0, 0), window=inner_frame, anchor="nw", tags="inner_frame")

    # Configure event to resize inner_frame
    def on_canvas_configure(event):
        canvas.itemconfig("inner_frame", width=event.width)
    canvas.bind("<Configure>", on_canvas_configure)

    # Bind mouse wheel scrolling to canvas
    def on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def on_mousewheel_up(event):
        canvas.yview_scroll(-1, "units")

    def on_mousewheel_down(event):
        canvas.yview_scroll(1, "units")

    canvas.bind("<MouseWheel>", on_mousewheel)
    canvas.bind("<Button-4>", on_mousewheel_up)
    canvas.bind("<Button-5>", on_mousewheel_down)

    # Configure left_frame grid
    left_frame.grid_columnconfigure(0, weight=1)
    left_frame.grid_rowconfigure(0, weight=2)
    left_frame.grid_rowconfigure(1, weight=3)

    # Initialize command tabs
    create_command_tabs(current_column_count)

    # User list in column 1
    user_list = Listbox(root)
    user_list.grid(row=0, column=1, sticky='nsew')
    user_list.bind('<Button-3>', on_right_click)

    # Entry field with bindings
    entry = tk.Entry(root)
    entry.grid(row=1, column=0, columnspan=2, sticky='ew')
    entry.bind('<Return>', send_message)
    entry.bind('<Up>', lambda event: navigate_history('up'))
    entry.bind('<Down>', lambda event: navigate_history('down'))
    entry.bind('<Button-3>', on_entry_right_click)

    # Configure main grid
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)

    # Dictionary to track private chat windows
    private_chat_windows = {}

    irc_thread = threading.Thread(target=irc_thread_func)
    irc_thread.daemon = True
    irc_thread.start()

    root.after(100, update_gui)
    root.mainloop()
