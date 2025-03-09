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

ZNC_SERVER = "<server ip>"
ZNC_PORT = <PORTNUM>
IRC_NICKNAME = "<ZNC Nick>"
ZNC_USERNAME = "<znc user> same as nick for now"
NETWORK = "<Irc network you setup in your bouncer"
ZNC_PASSWORD = "<password duh>"

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



# mIRC color mapping to Tkinter color names
mirc_colors = {
    '0': 'white', '1': 'black', '2': 'navy', '3': 'green', '4': 'red',
    '5': 'brown', '6': 'purple', '7': 'olive', '8': 'yellow', '9': 'lime',
    '10': 'darkcyan', '11': 'cyan', '12': 'skyblue', '13': 'fuchsia',
    '14': 'gray', '15': 'silver'
}

def parse_mirc_message(message):
    """Parse mIRC control codes and return segments with formatting state."""
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
        elif char in ['\x02', '\x1F', '\x0F']:  # Bold, Underline, Reset
            if current_text:
                segments.append((current_text, state.copy()))
                current_text = ''
            if char == '\x02':
                state['bold'] = not state['bold']
            elif char == '\x1F':
                state['underline'] = not state['underline']
            else:  # \x0F
                state = {'fg': 'default', 'bold': False, 'underline': False}
            i += 1
        else:
            current_text += char
            i += 1
    if current_text:
        segments.append((current_text, state.copy()))
    return segments

def get_tag_name(state):
    """Generate a tag name for mIRC formatting."""
    fg = state['fg'] if state['fg'] != 'default' else 'def'
    bold = 'b' if state['bold'] else ''
    underline = 'u' if state['underline'] else ''
    return f"tag_{fg}_{bold}_{underline}"

def load_commands():
    """Load commands from commands.txt and user_commands.txt."""
    commands = {"General": []}
    try:
        with open('commands.txt', 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        current_tab = "General"
        for line in lines:
            if line.startswith('[') and line.endswith(']'):
                current_tab = line[1:-1]
                commands[current_tab] = []
            else:
                commands[current_tab].append(line)
    except FileNotFoundError:
        logger.warning("commands.txt not found, using default.")

    user_commands = {"General": []}
    try:
        with open('user_commands.txt', 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        current_menu = "General"
        for line in lines:
            if line.startswith('[') and line.endswith(']'):
                current_menu = line[1:-1]
                user_commands[current_menu] = []
            else:
                user_commands[current_menu].append(line)
    except FileNotFoundError:
        logger.warning("user_commands.txt not found, using default.")

    return commands, user_commands

def load_games():
    """Load games from games.txt."""
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
                    logger.warning(f"Invalid line in games.txt: {line}")
    except FileNotFoundError:
        logger.warning("games.txt not found, no games loaded.")
    return games_dict

def open_game_window(game_name, actions):
    """Open a game window with buttons for actions."""
    game_window = tk.Toplevel(root)
    game_window.title(game_name)
    game_window.geometry("300x200")
    tk.Label(game_window, text=f"{game_name} Options", font=("Arial", 12, "bold")).pack(pady=10)
    for button_title, recipient, message in actions:
        btn = tk.Button(game_window, text=button_title,
                        command=lambda r=recipient, m=message: send_private_message(r, m))
        btn.pack(pady=5, padx=10, fill='x')

def send_private_message(recipient, message):
    """Send a private message."""
    send_queue.put(f"PRIVMSG {recipient} :{message}")
    logger.info(f"Queued private message to {recipient}: {message}")

class MyIRCClient(irc.client.SimpleIRCClient):
    """Custom IRC client for handling ZNC connections and events."""
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
            self.authenticated = True
            logger.info("Sent authentication and set authenticated flag")

    def on_welcome(self, connection, event):
        if self.authenticated:
            incoming_queue.put({'type': 'status', 'text': 'Connected'})
            connection.join('#pirates')
            logger.info("Connected to ZNC and joined #pirates")

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

    def on_part(self, connection, event):
        if event.target == '#pirates':
            nick = event.source.nick
            self.user_list = [u for u in self.user_list if u['nick'] != nick]
            incoming_queue.put({'type': 'part', 'user': nick})
            incoming_queue.put({'type': 'userlist', 'users': self.user_list})

    def on_quit(self, connection, event):
        nick = event.source.nick
        self.user_list = [u for u in self.user_list if u['nick'] != nick]
        incoming_queue.put({'type': 'quit', 'user': nick})
        incoming_queue.put({'type': 'userlist', 'users': self.user_list})

    def on_pubmsg(self, connection, event):
        if event.target == '#pirates':
            nick = event.source.nick
            message = event.arguments[0]
            incoming_queue.put({'type': 'message', 'user': nick, 'text': message})

    def on_privmsg(self, connection, event):
        nick = event.source.nick
        message = event.arguments[0]
        incoming_queue.put({'type': 'message' if nick.lower() == "captainjack" else 'notification',
                            'user': nick, 'text': message})

    def on_namreply(self, connection, event):
        if event.arguments[1] == '#pirates':
            self.user_list.clear()
            for nick in event.arguments[2].split():
                is_op = nick.startswith('@')
                is_voiced = nick.startswith('+')
                clean_nick = nick.lstrip('@+')
                self.user_list.append({'nick': clean_nick, 'op': is_op, 'voiced': is_voiced and not is_op, 'away': False})

    def on_endofnames(self, connection, event):
        if event.arguments[1] == '#pirates':
            incoming_queue.put({'type': 'userlist', 'users': self.user_list})

    def on_mode(self, connection, event):
        if event.target == '#pirates':
            modes = event.arguments[0]
            affected_nicks = event.arguments[1:]
            for nick in affected_nicks:
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

def irc_thread_func():
    """Run the IRC client in a separate thread."""
    incoming_queue.put({'type': 'status', 'text': 'Connecting...'})
    client = MyIRCClient(IRC_NICKNAME, ZNC_USERNAME, NETWORK, ZNC_PASSWORD)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_socket = context.wrap_socket(raw_socket, server_hostname=ZNC_SERVER)
        ssl_socket.connect((ZNC_SERVER, ZNC_PORT))
        client.connect(ZNC_SERVER, ZNC_PORT, IRC_NICKNAME, connect_factory=lambda x: ssl_socket)
    except Exception as e:
        incoming_queue.put({'type': 'status', 'text': f'Connection failed: {str(e)}'})
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
        while not raw_send_queue.empty():
            client.connection.send_raw(raw_send_queue.get())

def send_message(event=None):
    """Send a message from the entry field."""
    global history_index
    message = entry.get().strip()
    if message:
        send_queue.put(message)
        message_history.append(message)
        if len(message_history) > 100:
            message_history.pop(0)
        entry.delete(0, END)
        history_index = -1

def navigate_history(direction):
    """Navigate through message history with arrow keys."""
    global history_index
    if not message_history:
        return
    if direction == 'up' and history_index != 0:
        history_index = len(message_history) - 1 if history_index == -1 else history_index - 1
    elif direction == 'down' and history_index != -1:
        history_index = history_index + 1 if history_index < len(message_history) - 1 else -1
    else:
        return
    entry.delete(0, END)
    if history_index != -1:
        entry.insert(0, message_history[history_index])

def refresh_commands():
    """Refresh command tabs from files."""
    global all_commands, current_user_commands
    commands, user_commands = load_commands()
    all_commands = commands
    current_user_commands = user_commands
    create_command_tabs(current_column_count)

def set_column_count(count):
    """Set the number of columns for command buttons."""
    global current_column_count
    current_column_count = count
    create_command_tabs(count)

def create_command_tabs(column_count):
    """Create tabs with command buttons."""
    for widget in cmd_frame.winfo_children():
        widget.destroy()
    notebook = ttk.Notebook(cmd_frame)
    notebook.pack(fill='both', expand=True)
    for tab_name, cmd_list in all_commands.items():
        tab = tk.Frame(notebook)
        notebook.add(tab, text=tab_name)
        for i, cmd in enumerate(cmd_list):
            btn = tk.Button(tab, text=cmd, command=lambda c=cmd: send_queue.put(c))
            btn.grid(row=i // column_count, column=i % column_count, sticky='ew', padx=2, pady=2)
        for c in range(column_count):
            tab.grid_columnconfigure(c, weight=1)

def on_right_click(event):
    """Handle right-click on user list."""
    try:
        index = user_list.nearest(event.y)
        user_list.selection_set(index)
        selection = user_list.get(index)
        nickname = selection.lstrip('👑🎙️👤🌙').split(' •')[0]
        menu = tk.Menu(root, tearoff=0)
        for menu_name, cmd_list in current_user_commands.items():
            sub_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label=menu_name, menu=sub_menu)
            for cmd in cmd_list:
                formatted_cmd = cmd.replace('<user>', nickname)
                sub_menu.add_command(label=formatted_cmd, command=lambda c=formatted_cmd: send_queue.put(c))
        menu.add_separator()
        menu.add_command(label="Customize Color", command=lambda: customize_user_color(nickname))
        menu.post(event.x_root, event.y_root)
    except Exception as e:
        logger.error(f"Right-click error: {str(e)}")

def load_user_colors():
    """Load user colors from colors.txt."""
    user_colors = {}
    try:
        with open('colors.txt', 'r') as f:
            for line in f:
                username, color = line.strip().split(',')
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
    """Set a user's message background color."""
    color = colorchooser.askcolor(title=f"Choose color for {username}")
    if color:
        user_colors[username] = color[1]
        save_user_colors()
        chat_area.tag_configure(f"user_{username}", background=color[1], spacing3=5)

def on_message_area_right_click(event):
    """Show right-click menu in chat area with commands."""
    menu = tk.Menu(root, tearoff=0)
    for tab_name, cmd_list in all_commands.items():
        sub_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label=tab_name, menu=sub_menu)
        for cmd in cmd_list:
            sub_menu.add_command(label=cmd, command=lambda c=cmd: send_queue.put(c))
    menu.post(event.x_root, event.y_root)

def update_gui():
    """Update GUI with IRC events."""
    while not incoming_queue.empty():
        event = incoming_queue.get()
        chat_area.config(state='normal')
        if event['type'] == 'message':
            username = event['user']
            user_tag = f"user_{username}" if username in user_colors else 'default'
            line = f"{username:<20}   {event['text']}\n"
            start_idx = chat_area.index('end')
            chat_area.insert('end', line, user_tag)
            bold_start = start_idx
            bold_end = f"{start_idx}+{len(username)}c"
            chat_area.tag_add('bold', bold_start, bold_end)
            message_start = f"{start_idx}+{len(username) + 3}c"
            current_pos = message_start
            for text, state in parse_mirc_message(event['text']):
                tag_name = get_tag_name(state)
                if tag_name not in chat_area.tag_names():
                    options = {
                        'foreground': mirc_colors.get(state['fg'], 'black') if state['fg'] != 'default' else 'black',
                        'font': ('Courier', 10, 'bold' if state['bold'] else 'normal'),
                        'underline': state['underline']
                    }
                    chat_area.tag_configure(tag_name, **options)
                chat_area.tag_add(tag_name, current_pos, f"{current_pos}+{len(text)}c")
                current_pos = f"{current_pos}+{len(text)}c"
        elif event['type'] == 'status':
            chat_area.insert('end', f"{' ':>20}   *** {event['text']}\n", 'default')
        elif event['type'] == 'notification':
            chat_area.insert('end', f"{' ':>20}   notification: <{event['user']}> {event['text']}\n", 'default')
        elif event['type'] in ['join', 'part', 'quit']:
            action = 'joined' if event['type'] == 'join' else 'left' if event['type'] == 'part' else 'quit'
            chat_area.insert('end', f"{' ':>20}   --> {event['user']} has {action}\n", 'default')
        elif event['type'] == 'userlist':
            user_list.delete(0, 'end')
            for user in event['users']:
                prefix = '👑' if user['op'] else '🎙️' if user['voiced'] else '🌙' if user['away'] else '👤'
                user_list.insert('end', f"{prefix}{user['nick']}")
        chat_area.config(state='disabled')
        chat_area.see('end')
    root.after(100, update_gui)

# Service-related globals
service_running = False
stop_event = None
server_thread = None
client_infos = []
client_queues_lock = threading.Lock()

def run_service(port, stop_event):
    """Run a service to handle external client connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(1.0)
    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        logger.info(f"Service listening on port {port}")
        while not stop_event.is_set():
            try:
                client_socket, addr = server_socket.accept()
                client_queue = queue.Queue()
                with client_queues_lock:
                    client_infos.append((client_socket, client_queue))
                threading.Thread(target=client_reader, args=(client_socket, raw_send_queue, stop_event, client_infos), daemon=True).start()
                threading.Thread(target=client_writer, args=(client_socket, client_queue, stop_event, client_infos), daemon=True).start()
                logger.info(f"Client connected: {addr}")
            except socket.timeout:
                continue
    finally:
        server_socket.close()
        with client_queues_lock:
            for cs, _ in client_infos:
                cs.close()
            client_infos.clear()

def client_reader(client_socket, raw_send_queue, stop_event, client_infos):
    """Read from service client and send to IRC."""
    try:
        while not stop_event.is_set():
            data = client_socket.recv(1024)
            if not data:
                break
            command = data.decode('utf-8', errors='ignore').strip()
            if command:
                raw_send_queue.put(command)
    finally:
        with client_queues_lock:
            client_infos[:] = [(cs, cq) for cs, cq in client_infos if cs != client_socket]
        client_socket.close()

def client_writer(client_socket, client_queue, stop_event, client_infos):
    """Write IRC messages to service client."""
    try:
        while not stop_event.is_set():
            message = client_queue.get(timeout=1.0)
            client_socket.send(message.encode('utf-8'))
    except queue.Empty:
        pass
    finally:
        with client_queues_lock:
            client_infos[:] = [(cs, cq) for cs, cq in client_infos if cs != client_socket]
        client_socket.close()

if __name__ == '__main__':
    root = tk.Tk()
    root.title("2600 Pirates IRC")

    # Menubar setup
    menubar = tk.Menu(root)
    root.config(menu=menubar)
    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Refresh Commands", command=refresh_commands)
    column_menu = tk.Menu(file_menu, tearoff=0)
    file_menu.add_cascade(label="Column Count", menu=column_menu)
    for count in [3, 4, 5, 6]:
        column_menu.add_command(label=str(count), command=lambda c=count: set_column_count(c))
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)

    games_dict = load_games()
    games_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Interactive Games", menu=games_menu)
    for game_name, actions in games_dict.items():
        games_menu.add_command(label=game_name, command=lambda gn=game_name, acts=actions: open_game_window(gn, acts))

    # Load commands and colors
    all_commands, current_user_commands = load_commands()
    user_colors = load_user_colors()

    # GUI layout
    left_frame = tk.Frame(root)
    left_frame.grid(row=0, column=0, sticky='nsew')
    cmd_frame = tk.Frame(left_frame)
    cmd_frame.grid(row=0, column=0, sticky='nsew')
    chat_area = scrolledtext.ScrolledText(left_frame, state='disabled', wrap='word', font=('Courier', 10), spacing1=5, spacing3=5)
    chat_area.grid(row=1, column=0, sticky='nsew')
    chat_area.bind('<Button-3>', on_message_area_right_click)

    # Configure chat area tags
    chat_area.tag_configure('default', background='white', spacing3=5)
    chat_area.tag_configure('bold', font=('Courier', 10, 'bold'))
    for username, color in user_colors.items():
        chat_area.tag_configure(f"user_{username}", background=color, spacing3=5)

    left_frame.grid_rowconfigure(0, weight=2)
    left_frame.grid_rowconfigure(1, weight=3)
    left_frame.grid_columnconfigure(0, weight=1)

    create_command_tabs(current_column_count)

    user_list = Listbox(root)
    user_list.grid(row=0, column=1, sticky='nsew')
    user_list.bind('<Button-3>', on_right_click)

    entry = tk.Entry(root)
    entry.grid(row=1, column=0, columnspan=2, sticky='ew')
    entry.bind('<Return>', send_message)
    entry.bind('<Up>', lambda e: navigate_history('up'))
    entry.bind('<Down>', lambda e: navigate_history('down'))

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)

    # Start IRC thread
    threading.Thread(target=irc_thread_func, daemon=True).start()
    root.after(100, update_gui)
    root.mainloop()
