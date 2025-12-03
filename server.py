# --- МАГИЯ ASYNC (ОБЯЗАТЕЛЬНО В НАЧАЛЕ ФАЙЛА) ---
import eventlet
eventlet.monkey_patch()

import os
import uuid
import json
import base64
from datetime import datetime
from flask import Flask, render_template, request, send_from_directory, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- КОНФИГУРАЦИЯ ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret_go_game_key_v16_no_bugs')
basedir = os.path.abspath(os.path.dirname(__file__))

database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///' + os.path.join(basedir, 'go_game.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_size": 10,
    "max_overflow": 20,
    "pool_recycle": 1800,
}

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# --- Модели БД ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    wins = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)
    elo = db.Column(db.Integer, default=1000)
    avatar = db.Column(db.Text, default=None) 

class GameRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    player_black = db.Column(db.String(80))
    player_white = db.Column(db.String(80))
    winner_color = db.Column(db.Integer) 
    result_text = db.Column(db.String(50)) 
    elo_delta = db.Column(db.Integer, default=0) 
    states_json = db.Column(db.Text) 
    chat_json = db.Column(db.Text)

with app.app_context():
    db.create_all()

# --- Структуры данных (In-Memory) ---
online_users = {} 
games = {} 

# --- Звуки ---
@app.route('/stone.mp3')
def serve_stone():
    return send_from_directory(basedir, 'stone.mp3')

@app.route('/ding.mp3')
def serve_ding():
    return send_from_directory(basedir, 'ding.mp3')

@app.route('/eat.mp3')
def serve_eat():
    return send_from_directory(basedir, 'eat.mp3')

@app.route('/')
def index():
    return render_template('index.html')

# --- KEEP ALIVE ---
@app.route('/keep_alive')
def keep_alive():
    return "OK", 200

# --- SGF Генерация ---
@app.route('/download_sgf/<int:record_id>')
def download_sgf(record_id):
    record = GameRecord.query.get(record_id)
    if not record:
        return "Game not found", 404

    sgf = "(;GM[1]FF[4]CA[UTF-8]AP[JabiGo:v33]ST[2]\n"
    sgf += f"RU[Japanese]SZ[13]KM[6.5]\n"
    sgf += f"PW[{record.player_white}]PB[{record.player_black}]\n"
    sgf += f"DT[{record.date.strftime('%Y-%m-%d')}]\n"
    if record.result_text:
        res = record.result_text.replace("Ч", "B").replace("Б", "W").replace(" ", "")
        sgf += f"RE[{res}]\n"

    states = json.loads(record.states_json)
    
    def coord_to_sgf(val):
        return chr(ord('a') + val)

    for i in range(1, len(states)):
        st = states[i]
        lm = st.get('last_move')
        color_tag = "B" if st['current_player'] == 2 else "W"
        
        if lm is None:
            sgf += f";{color_tag}[]"
        else:
            x = coord_to_sgf(lm['x'])
            y = coord_to_sgf(lm['y'])
            sgf += f";{color_tag}[{x}{y}]"

    sgf += ")"

    response = make_response(sgf)
    filename = f"game_{record_id}_{record.player_black}_vs_{record.player_white}.sgf"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "application/x-go-sgf"
    return response

# --- Логика игры ---
def create_game_session(challenger_sid, challenger_name, opponent_sid, opponent_name):
    game_id = str(uuid.uuid4())[:8]
    initial_state = {
        'board': [[0]*13 for _ in range(13)],
        'current_player': 1,
        'prisoners': {1: 0, 2: 0},
        'ko_position': None,
        'consecutive_passes': 0,
        'dead_stones': [],
        'last_move': None
    }
    
    u1 = User.query.filter_by(username=challenger_name).first()
    u2 = User.query.filter_by(username=opponent_name).first()
    av1 = u1.avatar if u1 else None
    av2 = u2.avatar if u2 else None

    games[game_id] = {
        'id': game_id,
        'phase': 'SETUP', 
        'setup_players': {
            'challenger': {'sid': challenger_sid, 'name': challenger_name, 'avatar': av1},
            'opponent': {'sid': opponent_sid, 'name': opponent_name, 'avatar': av2}
        },
        'players': {}, 
        'spectators': [],
        'chat_history': [],
        'full_history': [initial_state], 
        'current_state': initial_state,
        'confirmed_players': [],
        'result_text': None,
        'elo_delta': 0,
        'final_elos': {},
        'is_resign': False 
    }
    return game_id

def calculate_elo(winner_elo, loser_elo):
    K = 32
    expected_winner = 1 / (1 + 10 ** ((loser_elo - winner_elo) / 400))
    diff = K * (1 - expected_winner)
    return round(diff)

# --- Socket события ---

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in online_users:
        u = online_users[sid]
        for gid, g in games.items():
            if u['username'] in g['spectators']:
                g['spectators'].remove(u['username'])
        del online_users[sid]
        broadcast_lobby_state()

@socketio.on('login')
def handle_login(data):
    username = data['username'].strip()
    password = data['password'].strip()
    
    if not username or not password:
        emit('login_error', {'msg': 'Пустые поля'})
        return

    user = User.query.filter_by(username=username).first()
    if user:
        if not check_password_hash(user.password_hash, password):
            emit('login_error', {'msg': 'Неверный пароль'})
            return
    else:
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(username=username, password_hash=hashed)
        db.session.add(user)
        db.session.commit()

    sids_to_remove = [k for k, v in online_users.items() if v['username'] == user.username]
    for old_sid in sids_to_remove:
        if old_sid in online_users: del online_users[old_sid]
        leave_room('lobby', sid=old_sid)

    online_users[request.sid] = {
        'user_id': user.id,
        'username': user.username,
        'elo': user.elo,
        'status': 'lobby',
        'game_id': None
    }
    
    join_room('lobby')
    emit('login_success', {'username': user.username, 'elo': user.elo})
    
    # Реконнект
    active_gid = None
    for gid, g in games.items():
        if g['phase'] != 'FINISHED':
            p1 = g['players'].get(1, {})
            p2 = g['players'].get(2, {})
            if p1.get('name') == user.username or p2.get('name') == user.username:
                active_gid = gid
                break
            if g['phase'] == 'SETUP':
                 s1 = g['setup_players']['challenger']
                 s2 = g['setup_players']['opponent']
                 if s1['name'] == user.username or s2['name'] == user.username:
                     active_gid = gid
                     break

    if active_gid:
        online_users[request.sid]['status'] = 'playing'
        online_users[request.sid]['game_id'] = active_gid
        join_room(active_gid)
        
        g = games[active_gid]
        
        if g['phase'] == 'SETUP':
            if g['setup_players']['challenger']['name'] == user.username:
                g['setup_players']['challenger']['sid'] = request.sid
                role = 'challenger'
            else:
                g['setup_players']['opponent']['sid'] = request.sid
                role = 'opponent'
            emit('game_start', {'game_id': active_gid, 'state': sanitize_game(g), 'role': role, 'is_new_game': False})
        else:
            role = 0
            if g['players'].get(1, {}).get('name') == user.username:
                g['players'][1]['sid'] = request.sid
                role = 1
            elif g['players'].get(2, {}).get('name') == user.username:
                g['players'][2]['sid'] = request.sid
                role = 2
            emit('game_start', {'game_id': active_gid, 'state': sanitize_game(g), 'role': role, 'is_new_game': False})

    broadcast_lobby_state()

@socketio.on('refresh_lobby')
def handle_refresh_lobby():
    join_room('lobby') 
    broadcast_lobby_state()

@socketio.on('request_sync')
def handle_sync(data):
    gid = data.get('game_id')
    if gid and gid in games:
        join_room(gid)
        g = games[gid]
        emit('update_game', sanitize_game(g))

def broadcast_lobby_state():
    users_list = []
    for k, v in online_users.items():
        u_db = User.query.get(v['user_id'])
        
        current_status = v['status']
        gid = v['game_id']
        if current_status == 'playing' and (not gid or gid not in games or games[gid]['phase'] == 'FINISHED'):
             current_status = 'lobby'

        users_list.append({
            'sid': k, 
            'username': v['username'], 
            'elo': v['elo'], 
            'status': current_status,
            'wins': u_db.wins,
            'losses': u_db.losses,
            'avatar': u_db.avatar
        })
    
    active_games = []
    for gid, g in games.items():
        if g['phase'] != 'SETUP' and g['phase'] != 'FINISHED' and 1 in g['players']:
            p1 = g['players'][1]['name']
            p2 = g['players'][2]['name']
            desc = f"Ч: {p1} / Б: {p2}"
            active_games.append({'id': gid, 'desc': desc, 'spectators': len(g['spectators']), 'p1': p1, 'p2': p2})

    recent_db = GameRecord.query.order_by(GameRecord.date.desc()).limit(8).all()
    finished_list = []
    for r in recent_db:
        # Добавляем дату в ответ для лобби
        finished_list.append({
            'id': r.id,
            'p_black': r.player_black,
            'p_white': r.player_white,
            'result': r.result_text,
            'winner_color': r.winner_color,
            'date': r.date.isoformat() 
        })

    emit('lobby_update', {'users': users_list, 'games': active_games, 'finished': finished_list}, room='lobby')

# --- LEADERBOARD ---
@socketio.on('get_leaderboard')
def handle_get_leaderboard():
    users_db = User.query.order_by(User.elo.desc()).limit(100).all()
    lb_data = []
    for u in users_db:
        lb_data.append({
            'username': u.username,
            'elo': u.elo,
            'wins': u.wins,
            'losses': u.losses,
            'total': u.wins + u.losses,
            'avatar': u.avatar
        })
    emit('leaderboard_data', lb_data)

# --- TOOLTIP ---
@socketio.on('get_tooltip_data')
def handle_tooltip_request(data):
    target_username = data.get('username')
    user = User.query.filter_by(username=target_username).first()
    if user:
        emit('tooltip_data_response', {
            'username': user.username,
            'elo': user.elo,
            'wins': user.wins,
            'losses': user.losses,
            'avatar': user.avatar
        })

# --- PROFILE ---
@socketio.on('get_profile')
def handle_get_profile(data):
    target_username = data.get('username')
    requester = online_users.get(request.sid)
    
    if target_username:
        user_db = User.query.filter_by(username=target_username).first()
    elif requester:
        user_db = User.query.get(requester['user_id'])
    else:
        return

    if not user_db: return

    is_own = False
    if requester and requester['username'] == user_db.username:
        is_own = True
    
    history_recs = GameRecord.query.filter(
        (GameRecord.player_black == user_db.username) | (GameRecord.player_white == user_db.username)
    ).order_by(GameRecord.date.desc()).limit(20).all()
    
    history_data = []
    for r in history_recs:
        my_color = 1 if r.player_black == user_db.username else 2
        opponent = r.player_white if my_color == 1 else r.player_black
        is_win = (r.winner_color == my_color)
        delta = r.elo_delta if is_win else -r.elo_delta
        
        history_data.append({
            'game_id': r.id,
            'date': r.date.isoformat() + 'Z',
            'opponent': opponent,
            'my_color': my_color,
            'result': r.result_text,
            'elo_diff': delta,
            'is_win': is_win 
        })

    emit('profile_data', {
        'username': user_db.username,
        'elo': user_db.elo,
        'wins': user_db.wins,
        'losses': user_db.losses,
        'avatar': user_db.avatar,
        'history': history_data,
        'is_own': is_own
    })

@socketio.on('upload_avatar')
def handle_avatar_upload(data):
    u = online_users.get(request.sid)
    if not u: return
    
    image_data = data.get('image') 
    if not image_data: return
    
    user_db = User.query.get(u['user_id'])
    user_db.avatar = image_data
    db.session.commit()
    
    emit('server_notification', {'msg': 'Аватар обновлен!'})
    handle_get_profile({'username': u['username']})

# --- HISTORY & REPLAY ---
@socketio.on('get_all_history')
def handle_get_history():
    records = GameRecord.query.order_by(GameRecord.date.desc()).limit(50).all()
    data = []
    for r in records:
        iso_date = r.date.isoformat() + 'Z'
        data.append({
            'id': r.id,
            'date': iso_date,
            'p_black': r.player_black,
            'p_white': r.player_white,
            'result': r.result_text,
            'winner_color': r.winner_color 
        })
    emit('history_list', data)

@socketio.on('get_replay_data')
def handle_replay(data):
    rec_id = data['record_id']
    record = GameRecord.query.get(rec_id)
    if not record: return
    
    if request.sid in online_users and online_users[request.sid]['status'] != 'playing':
        online_users[request.sid]['game_id'] = None 
        broadcast_lobby_state()

    states = json.loads(record.states_json)
    chat = json.loads(record.chat_json)
    
    u1 = User.query.filter_by(username=record.player_black).first()
    u2 = User.query.filter_by(username=record.player_white).first()
    
    emit('replay_data', {
        'id': record.id,
        'p_black': record.player_black,
        'p_white': record.player_white,
        'av_black': u1.avatar if u1 else None,
        'av_white': u2.avatar if u2 else None,
        'result': record.result_text,
        'winner_color': record.winner_color,
        'states': states,
        'chat': chat
    })

# --- GAME SETUP ---
@socketio.on('send_challenge')
def handle_challenge_req(data):
    target_sid = data['target_sid']
    me = online_users.get(request.sid)
    target = online_users.get(target_sid)
    
    is_target_playing = False
    tgid = target.get('game_id')
    if tgid and tgid in games and games[tgid]['phase'] != 'FINISHED':
        is_target_playing = True
    
    if me and target and not is_target_playing:
        emit('incoming_challenge', {'challenger_sid': request.sid, 'challenger_name': me['username'], 'challenger_elo': me['elo']}, room=target_sid)

@socketio.on('respond_challenge')
def handle_challenge_resp(data):
    if not data['accepted']:
        emit('server_notification', {'msg': 'Вызов отклонен.'}, room=data['challenger_sid'])
        return
        
    c_sid, me_sid = data['challenger_sid'], request.sid
    c_user, me_user = online_users.get(c_sid), online_users.get(me_sid)
    
    c_gid = c_user.get('game_id')
    me_gid = me_user.get('game_id')
    c_playing = c_gid and c_gid in games and games[c_gid]['phase'] != 'FINISHED'
    me_playing = me_gid and me_gid in games and games[me_gid]['phase'] != 'FINISHED'

    if c_user and me_user and not c_playing and not me_playing:
        gid = create_game_session(c_sid, c_user['username'], me_sid, me_user['username'])
        c_user.update({'status': 'playing', 'game_id': gid})
        me_user.update({'status': 'playing', 'game_id': gid})
        
        leave_room('lobby', sid=c_sid); leave_room('lobby', sid=me_sid)
        join_room(gid, sid=c_sid); join_room(gid, sid=me_sid)
        
        g = games[gid]
        emit('game_start', {'game_id': gid, 'state': sanitize_game(g), 'role': 'challenger', 'is_new_game': True}, room=c_sid)
        emit('game_start', {'game_id': gid, 'state': sanitize_game(g), 'role': 'opponent', 'is_new_game': True}, room=me_sid)
        broadcast_lobby_state()

@socketio.on('setup_pick_color')
def handle_pick_color(data):
    sid = request.sid
    user = online_users.get(sid)
    if not user or not user['game_id']: return
    g = games.get(user['game_id'])
    if not g or g['phase'] != 'SETUP': return
    
    if g['setup_players']['challenger']['sid'] != sid: return
    
    w_col = int(data['color'])
    other_col = 2 if w_col == 1 else 1
    
    g['players'][w_col] = g['setup_players']['challenger']
    g['players'][other_col] = g['setup_players']['opponent']
    g['phase'] = 'PLAYING'
    
    c_sid = g['setup_players']['challenger']['sid']
    o_sid = g['setup_players']['opponent']['sid']
    
    emit('setup_complete', {'role': w_col}, room=c_sid)
    emit('setup_complete', {'role': other_col}, room=o_sid)
    emit('update_game', sanitize_game(g), room=g['id'])
    broadcast_lobby_state()

# --- GAMEPLAY ---
def get_game_and_role(sid):
    u = online_users.get(sid)
    if not u or not u['game_id']: return None, None
    g = games.get(u['game_id'])
    if not g or g['phase'] == 'SETUP': return None, 0
    role = 0
    if 1 in g['players'] and g['players'][1]['sid'] == sid: role = 1
    elif 2 in g['players'] and g['players'][2]['sid'] == sid: role = 2
    return g, role

@socketio.on('make_move')
def handle_move(data):
    g, role = get_game_and_role(request.sid)
    if not g or role != g['current_state']['current_player']: return

    new_state = {
        'board': data['board'],
        'current_player': 2 if g['current_state']['current_player'] == 1 else 1,
        'prisoners': data['prisoners'],
        'ko_position': data['ko'],
        'consecutive_passes': 0,
        'dead_stones': [],
        'last_move': {'x': data['move_x'], 'y': data['move_y']}
    }
    g['current_state'] = new_state
    g['full_history'].append(new_state) 
    
    emit('update_game', sanitize_game(g), room=g['id'])

@socketio.on('pass_move')
def handle_pass():
    g, role = get_game_and_role(request.sid)
    if not g or role != g['current_state']['current_player']: return

    passes = g['current_state']['consecutive_passes'] + 1
    new_state = {
        'board': [r[:] for r in g['current_state']['board']],
        'current_player': 2 if g['current_state']['current_player'] == 1 else 1,
        'prisoners': g['current_state']['prisoners'].copy(),
        'ko_position': None,
        'consecutive_passes': passes,
        'dead_stones': [],
        'last_move': None
    }
    g['current_state'] = new_state
    g['full_history'].append(new_state)

    if passes >= 2:
        g['phase'] = 'SCORING'
        g['confirmed_players'] = []
    
    emit('update_game', sanitize_game(g), room=g['id'])

@socketio.on('request_undo')
def handle_undo_req():
    g, role = get_game_and_role(request.sid)
    if not g or role == 0 or g['phase'] != 'PLAYING': return
    if len(g['full_history']) <= 1: return 

    opp_role = 2 if role == 1 else 1
    opp_sid = g['players'][opp_role]['sid']
    requester_name = g['players'][role]['name']
    emit('undo_requested', {'requester': requester_name}, room=opp_sid)

@socketio.on('respond_undo')
def handle_undo_resp(data):
    g, role = get_game_and_role(request.sid)
    if not g or role == 0: return
    
    accepted = data['accepted']
    opp_role = 2 if role == 1 else 1
    opp_sid = g['players'][opp_role]['sid']
    
    if not accepted:
        emit('server_notification', {'msg': 'Соперник отклонил возврат хода.'}, room=opp_sid)
        return

    if len(g['full_history']) > 1:
        g['full_history'].pop() 
        g['current_state'] = g['full_history'][-1] 
        emit('update_game', sanitize_game(g), room=g['id'])
        emit('server_notification', {'msg': 'Ход возвращен.'}, room=g['id'])

@socketio.on('confirm_score')
def handle_confirm_score(data):
    g, role = get_game_and_role(request.sid)
    if not g or role == 0 or g['phase'] != 'SCORING': return

    if role not in g['confirmed_players']:
        g['confirmed_players'].append(role)
    emit('update_game', sanitize_game(g), room=g['id'])

    if len(g['confirmed_players']) >= 2:
        finish_match_logic(g, data['winner_color'], is_resign=False, diff=data['diff'])

@socketio.on('resume_game')
def handle_resume_game():
    g, role = get_game_and_role(request.sid)
    if not g or role == 0 or g['phase'] != 'SCORING': return
    g['phase'] = 'PLAYING'
    g['current_state']['consecutive_passes'] = 0
    g['confirmed_players'] = []
    emit('update_game', sanitize_game(g), room=g['id'])
    emit('server_notification', {'msg': 'Игра продолжена.'}, room=g['id'])

@socketio.on('resign')
def handle_resign():
    g, role = get_game_and_role(request.sid)
    if not g or role == 0: return
    winner = 2 if role == 1 else 1
    finish_match_logic(g, winner, is_resign=True)

def finish_match_logic(g, winner_color, is_resign=False, diff=0):
    p1, p2 = g['players'][1], g['players'][2]
    
    winner_name = p1['name'] if winner_color == 1 else p2['name']
    loser_name = p2['name'] if winner_color == 1 else p1['name']
    w_user = User.query.filter_by(username=winner_name).first()
    l_user = User.query.filter_by(username=loser_name).first()
    
    delta = 0
    if w_user and l_user:
        delta = calculate_elo(w_user.elo, l_user.elo)
        w_user.elo += delta
        w_user.wins += 1
        l_user.elo -= delta
        l_user.losses += 1
        db.session.commit()
        
        for sid, u in online_users.items():
            if u['username'] == winner_name: u['elo'] = w_user.elo
            if u['username'] == loser_name: u['elo'] = l_user.elo

    g['phase'] = 'FINISHED'
    win_char = "Ч" if winner_color == 1 else "Б"
    reason = "сдача" if is_resign else f"+{diff}"
    result_str = f"+{win_char} ({reason})"
    
    g['result_text'] = result_str
    g['winner_color'] = winner_color
    g['elo_delta'] = delta 
    g['final_elos'] = {
        winner_color: w_user.elo,
        (2 if winner_color == 1 else 1): l_user.elo
    }
    g['is_resign'] = is_resign
    g['current_state']['dead_stones'] = []

    record = GameRecord(
        player_black=p1['name'],
        player_white=p2['name'],
        winner_color=winner_color,
        result_text=result_str,
        elo_delta=delta,
        states_json=json.dumps(g['full_history']),
        chat_json=json.dumps(g['chat_history'])
    )
    db.session.add(record)
    db.session.commit()
    
    g['db_record_id'] = record.id

    emit('update_game', sanitize_game(g), room=g['id'])

    msg = f"Матч завершен! Победа {win_char} ({reason}). Рейтинг: {winner_name}({w_user.elo}), {loser_name}({l_user.elo})"
    emit('server_notification', {'msg': msg}, room=g['id'])
    broadcast_lobby_state()

@socketio.on('send_message')
def handle_msg(data):
    sid = request.sid
    u = online_users.get(sid)
    if not u or not u['game_id']: return
    g = games.get(u['game_id'])
    if not g: return
    color = 0
    if g['phase'] != 'SETUP':
        if 1 in g['players'] and g['players'][1]['sid'] == sid: color = 1
        elif 2 in g['players'] and g['players'][2]['sid'] == sid: color = 2
    
    move_num = len(g['full_history']) - 1
    msg_obj = {
        'user': u['username'], 
        'color': color, 
        'text': data['message'],
        'move': move_num
    }
    
    g['chat_history'].append(msg_obj)
    
    if g['phase'] == 'FINISHED' and g.get('db_record_id'):
        rec = GameRecord.query.get(g['db_record_id'])
        if rec:
            rec.chat_json = json.dumps(g['chat_history'])
            db.session.commit()

    emit('new_message', msg_obj, room=g['id'])

@socketio.on('toggle_dead_stone')
def handle_dead(data):
    g, r = get_game_and_role(request.sid)
    if g and r and g['phase'] == 'SCORING':
        ds = g['current_state']['dead_stones']
        k = data['key']
        if k in ds: ds.remove(k)
        else: ds.append(k)
        g['confirmed_players'] = []
        emit('update_dead_stones', ds, room=g['id'])
        emit('update_game', sanitize_game(g), room=g['id'])

@socketio.on('leave_game')
def handle_leave():
    sid = request.sid
    u = online_users.get(sid)
    if u:
        gid = u.get('game_id')
        if gid:
            leave_room(gid)
            if gid in games and u['username'] in games[gid]['spectators']:
                games[gid]['spectators'].remove(u['username'])

            if gid in games and games[gid]['phase'] == 'FINISHED':
                u['game_id'] = None
                u['status'] = 'lobby'
                active = 0
                for user in online_users.values():
                    if user.get('game_id') == gid: active += 1
                if active == 0: del games[gid]
            elif not gid in games:
                u['game_id'] = None
                u['status'] = 'lobby'
        
        is_active_player = False
        if gid and gid in games:
             g = games[gid]
             if g['phase'] != 'FINISHED':
                 p1 = g['players'].get(1, {})
                 p2 = g['players'].get(2, {})
                 if p1.get('name') == u['username'] or p2.get('name') == u['username']:
                     is_active_player = True
        
        if not is_active_player:
            u['status'] = 'lobby'
            u['game_id'] = None

        join_room('lobby')
        emit('return_to_lobby')
        broadcast_lobby_state()

@socketio.on('spectate_game')
def spectate(data):
    sid = request.sid
    gid = data['game_id']
    if gid in games:
        if online_users[sid]['status'] != 'playing':
            online_users[sid]['status'] = 'lobby' 
            online_users[sid]['game_id'] = gid
        
        leave_room('lobby'); join_room(gid)
        if online_users[sid]['username'] not in games[gid]['spectators']:
             games[gid]['spectators'].append(online_users[sid]['username'])
        emit('game_start', {'game_id': gid, 'state': sanitize_game(games[gid]), 'role': 0, 'is_new_game': False})
        broadcast_lobby_state()

def sanitize_game(g):
    p1 = g['players'].get(1, {})
    p2 = g['players'].get(2, {})
    
    return {
        'id': g['id'],
        'phase': g['phase'],
        'current_player': g['current_state']['current_player'],
        'board': g['current_state']['board'],
        'prisoners': g['current_state']['prisoners'],
        'dead_stones': g['current_state']['dead_stones'],
        'last_move': g['current_state']['last_move'],
        'consecutive_passes': g['current_state']['consecutive_passes'],
        'ko_position': g['current_state']['ko_position'],
        'move_count': len(g['full_history']) - 1, 
        'players_info': {
            1: {'name': p1.get('name', '...'), 'avatar': p1.get('avatar')}, 
            2: {'name': p2.get('name', '...'), 'avatar': p2.get('avatar')}
        },
        'confirmed_players': g.get('confirmed_players', []),
        'result_text': g.get('result_text'),
        'winner_color': g.get('winner_color'), 
        'elo_delta': g.get('elo_delta', 0),
        'final_elos': g.get('final_elos', {}),
        'chat_history': g['chat_history'],
        'full_history': g['full_history'], 
        'db_record_id': g.get('db_record_id'),
        'is_resign': g.get('is_resign', False)
    }

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
