#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext, Listbox, END, Menu, messagebox
from tkinter import ttk
import irc.client
import queue
import threading
import socket
import ssl
import logging
from PIL import Image, ImageTk, ImageEnhance
import tkinter.colorchooser as colorchooser



# Hardcoded ZNC connection details
ZNC_SERVER = "<server ip>"
ZNC_PORT = <PORTNUM>
IRC_NICKNAME = "<ZNC Nick>"
ZNC_USERNAME = "<znc user> same as nick for now"
NETWORK = "<Irc network you setup in your bouncer"
ZNC_PASSWORD = "<password duh>"


# Don't touch, for future dev
SERVER_IDENTIFIED_NICK=""

# Set up logging to console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Global queues for thread communication
incoming_queue = queue.Queue()  # IRC events to GUI
send_queue = queue.Queue()      # GUI messages to IRC
raw_send_queue = queue.Queue()  # Raw commands from service clients to IRC
user_colors = {}                # Username to color mapping
message_history = []            # List to store sent messages
history_index = -1              # Index to track position in history
current_column_count = 6        # Default column count

# Service-related globals
service_running = False
stop_event = None
server_thread = None
client_infos = []  # List of (client_socket, client_queue)
client_queues_lock = threading.Lock()



# mIRC color mapping to Tkinter color names
mirc_colors = {
    '0': 'white', '1': 'black', '2': 'navy', '3': 'green', '4': 'red',
    '5': 'brown', '6': 'purple', '7': 'olive', '8': 'yellow', '9': 'lime',
    '10': 'darkcyan', '11': 'cyan', '12': 'skyblue', '13': 'fuchsia',
    '14': 'gray', '15': 'silver'
}

# Load dictionary for Wordel helper
try:
    with open('filtered-american-english.txt', 'r') as f:
        dictionary = [word.strip().lower() for word in f]
except FileNotFoundError:
    logger.error("Dictionary file 'filtered-american-english.txt' not found.")
    dictionary = []

def match_word(word_pattern, word, exclude_chars='', include_chars=''):
    """Check if a word matches the pattern, excludes certain characters, and includes others."""
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
    """Parse the message for mIRC control codes and return segments with formatting state."""
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

def get_tag_name(state):
    """Generate a tag name for mIRC formatting, excluding background."""
    fg = state['fg'] if state['fg'] != 'default' else 'def'
    bold = 'b' if state['bold'] else ''
    underline = 'u' if state['underline'] else ''
    return f"tag_{fg}_{bold}_{underline}"

def load_commands():
    """Read commands from commands.txt and user_commands.txt, parsing tabs and sub-menus."""
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
    """Read games from games.txt with [game] as menu/window title and button,recipient,message lines."""
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
    """Open a new window with the game name as title and buttons for each action."""
    game_window = tk.Toplevel(root)
    game_window.title(game_name)
    game_window.geometry("300x200")
    tk.Label(game_window, text=f"{game_name} Options", font=("Arial", 12, "bold")).pack(pady=10)
    for button_title, recipient, message in actions:
        btn = tk.Button(game_window, text=button_title,
                        command=lambda r=recipient, m=message: send_private_message(r, m))
        btn.pack(pady=5, padx=10, fill='x')

def send_private_message(recipient, message):
    """Send a private message to the specified recipient."""
    send_queue.put(f"PRIVMSG {recipient} :{message}")
    logger.info(f"Queued private message to {recipient}: {message}")

def open_wordel_window():
    """Open a new window with text fields for Wordel Helper input and an output area."""
    wordel_window = tk.Toplevel(root)
    wordel_window.title("Wordel Helper")
    wordel_window.geometry("400x300")
    tk.Label(wordel_window, text="Matching Words").pack(pady=(5, 0))
    output_area = scrolledtext.ScrolledText(wordel_window, wrap='word', height=10, state='disabled')
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
    """Toggle the service on or off."""
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
    """Open the service settings window."""
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

class MyIRCClient(irc.client.SimpleIRCClient):
    def __init__(self, nickname, znc_username, network, znc_password):
        irc.client.SimpleIRCClient.__init__(self)
        self.nickname = nickname
        self.znc_username = znc_username
        self.network = network
        self.znc_password = znc_password
        self.user_list = []  # List of dicts: {'nick': 'name', 'op': bool, 'voiced': bool, 'away': bool}
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
        if nick.lower() == "captainjack":
            incoming_queue.put({'type': 'message', 'user': nick, 'text': f"(PM) {message}"})
        else:
            incoming_queue.put({'type': 'notification', 'user': nick, 'text': message})
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
    """Refresh commands from files and update the button layout."""
    global all_commands, current_user_commands
    commands, user_commands = load_commands()
    all_commands = commands
    current_user_commands = user_commands
    create_command_tabs(current_column_count)
    logger.info("Refreshed command tabs and user commands")

def set_column_count(count):
    """Set the current column count and update the command tabs."""
    global current_column_count
    current_column_count = count
    create_command_tabs(count)

def create_command_tabs(column_count):
    """Create notebook tabs with buttons arranged in specified number of columns."""
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

def on_right_click(event):
    try:
        index = user_list.nearest(event.y)
        user_list.selection_clear(0, END)
        user_list.selection_set(index)
        selection = user_list.get(index)
        logger.info(f"Raw selection from Listbox: '{selection}'")
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
            logger.warning(f"No known emoji found in selection: '{selection}'")
        logger.info(f"Extracted nickname: '{nickname}'")
        menu = tk.Menu(root, tearoff=0)
        for menu_name, cmd_list in current_user_commands.items():
            sub_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label=menu_name, menu=sub_menu)
            for cmd in cmd_list:
                formatted_cmd = cmd.replace('<user>', nickname)
                sub_menu.add_command(label=formatted_cmd, command=lambda c=formatted_cmd: send_queue.put(c))
        menu.add_separator()
        menu.add_command(label="customization", command=lambda: customize_user_color(nickname))
        menu.post(event.x_root, event.y_root)
        logger.info(f"Right-click menu opened for user: {nickname}")
    except Exception as e:
        logger.error(f"Failed to open right-click menu: {str(e)}")

def load_user_colors():
    """Load user colors from colors.txt into a dictionary."""
    user_colors = {}
    try:
        with open('colors.txt', 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 2:
                    username, color = parts
                    user_colors[username] = color
    except FileNotFoundError:
        pass
    return user_colors

def save_user_colors():
    """Save user colors to colors.txt."""
    with open('colors.txt', 'w') as f:
        for username, color in user_colors.items():
            f.write(f"{username},{color}\n")

def customize_user_color(username):
    """Open a color chooser dialog to set a user's message background color."""
    color = colorchooser.askcolor(title=f"Choose color for {username}")
    if color:
        hex_color = color[1]
        user_colors[username] = hex_color
        save_user_colors()
        tag = f"user_{username}"
        chat_area.tag_configure(tag, background=hex_color, spacing3=5)

def update_gui():
    """Update the GUI with incoming events."""
    while not incoming_queue.empty():
        event = incoming_queue.get()
        chat_area.config(state='normal')
        if event['type'] == 'message':
            username = event['user']
            username_width = 20
            user_tag = f"user_{username}" if username in user_colors else 'default'
            padding = ' ' * (username_width - len(username)) if len(username) <= username_width else ''
            full_line = padding + username + '   ' + event['text'] + '\n'
            start_idx = chat_area.index('end')
            chat_area.insert('end', full_line, user_tag)
            bold_start = f"{start_idx}+{len(padding)}c"
            bold_end = f"{start_idx}+{len(padding) + len(username)}c"
            chat_area.tag_add('bold', bold_start, bold_end)
            message_start = f"{start_idx}+{len(padding) + len(username) + 3}c"
            current_pos = message_start
            for text, state in parse_mirc_message(event['text']):
                segment_end = f"{current_pos}+{len(text)}c"
                tag_name = get_tag_name(state)
                if tag_name not in chat_area.tag_names():
                    options = {}
                    if state['fg'] != 'default':
                        options['foreground'] = mirc_colors.get(state['fg'], 'black')
                    options['font'] = ('Courier', 10, 'bold') if state['bold'] else ('Courier', 10)
                    if state['underline']:
                        options['underline'] = True
                    chat_area.tag_configure(tag_name, **options)
                chat_area.tag_add(tag_name, current_pos, segment_end)
                current_pos = segment_end
        elif event['type'] == 'status':
            chat_area.insert('end', f"{' ':>{20}}   *** {event['text']}\n", 'default')
        elif event['type'] == 'notification':
            chat_area.insert('end', f"{' ':>{20}}   notification: <{event['user']}> {event['text']}\n", 'default')
        elif event['type'] == 'join':
            chat_area.insert('end', f"{' ':>{20}}   --> {event['user']} has joined\n", 'default')
        elif event['type'] == 'part':
            chat_area.insert('end', f"{' ':>{20}}   <-- {event['user']} has left\n", 'default')
        elif event['type'] == 'quit':
            chat_area.insert('end', f"{' ':>{20}}   <-- {event['user']} has quit\n", 'default')
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
        chat_area.config(state='disabled')
        chat_area.see('end')
    root.after(100, update_gui)

def add_command_to_tab(tab_name, new_command):
    """Append a new command to the specified tab section in commands.txt."""
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
    """Add the current entry text to the specified tab and refresh the GUI."""
    new_command = entry.get().strip()
    if new_command:
        if add_command_to_tab(tab_name, new_command):
            refresh_commands()
        else:
            messagebox.showerror("Error", f"Tab '{tab_name}' not found in commands.txt")
    else:
        messagebox.showwarning("Warning", "No text in entry field to add.")

def on_entry_right_click(event):
    """Display a context menu with tab names and 'Add item' submenus on right-click in entry."""
    menu = tk.Menu(root, tearoff=0)
    for tab_name in all_commands.keys():
        sub_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label=tab_name, menu=sub_menu)
        sub_menu.add_command(label="Add item", command=lambda tn=tab_name: add_item_to_tab(tn))
    menu.post(event.x_root, event.y_root)

def on_message_area_right_click(event):
    """Display a context menu with commands from commands.txt on right-click in chat_area."""
    menu = tk.Menu(root, tearoff=0)
    for tab_name, cmd_list in all_commands.items():
        sub_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label=tab_name, menu=sub_menu)
        for cmd in cmd_list:
            sub_menu.add_command(label=cmd, command=lambda c=cmd: send_queue.put(c))
    menu.post(event.x_root, event.y_root)

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
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)

    # Interactive Games menu
    games_dict = load_games()
    games_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Interactive Games", menu=games_menu)
    for game_name, actions in games_dict.items():
        games_menu.add_command(label=game_name, command=lambda gn=game_name, acts=actions: open_game_window(gn, acts))

    # Helpers menu
    helpers_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Helpers", menu=helpers_menu)
    helpers_menu.add_command(label="Wordel", command=open_wordel_window)
    helpers_menu.add_command(label="Service", command=open_service_window)

    # Load initial commands
    commands, user_commands = load_commands()
    all_commands = commands
    current_user_commands = user_commands

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
    chat_area = scrolledtext.ScrolledText(
        left_frame,
        state='disabled',
        wrap='word',
        font=('Courier', 10),
        spacing1=5,
        spacing3=5
    )
    chat_area.grid(row=1, column=0, sticky='nsew')
    chat_area.bind('<Button-3>', on_message_area_right_click)  # Bind right-click event

    # Configure tags for user colors and default
    for username, color in user_colors.items():
        tag = f"user_{username}"
        chat_area.tag_configure(tag, background=color, spacing3=5)
    chat_area.tag_configure('default', background='white', spacing3=5)
    chat_area.tag_configure('bold', font=('Courier', 10, 'bold'))

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

    irc_thread = threading.Thread(target=irc_thread_func)
    irc_thread.daemon = True
    irc_thread.start()

    root.after(100, update_gui)
    root.mainloop()
