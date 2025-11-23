from flask import Flask, render_template, redirect

app = Flask(__name__, static_url_path='', static_folder='.')

@app.route('/')
def index():
    # 1. 메인 페이지 (200 OK)
    return render_template('index.html')

@app.route('/redirect-test')
def handle_redirect():
    # 2. 301 리다이렉트 발생
    # /redirect-test로 요청이 오면 /success 경로로 이동(301) 응답을 보냄
    return redirect("/success", code=301)

@app.route('/success')
def success_page():
    # 3. 리다이렉트 도착 페이지 (200 OK)
    return render_template('redirected-page.html')

if __name__ == '__main__':
    # host='0.0.0.0'은 내 컴퓨터의 모든 IP로 들어오는 연결을 허용하겠다는 뜻
    app.run(host='0.0.0.0', port=80, debug=False)