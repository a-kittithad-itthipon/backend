## Requirements

- Python 3.x
- pip

## Installation & Setup

Follow the steps below to set up the project locally:

1. Create a Virtual Environtment

```bash
py -3 -m venv .venv

or

python -m venv .venv
```

2. Activate the Virtual Environtment

Windows:

```bash
.venv\Scripts\activate
```

Mac/Linux:

```bash
source .venv/bin/activate
```

3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### Running the Application

Start the Flask server with:

1. app.py

```bash
python app.py
```

2. Celery
```bash
celery -A tasks worker --loglevel=info --pool=solo
```
3. Redis
```bash
docker run -d --name redis-server -p 6379:6379 redis
```

Once running, the app will typically be available at:

```bash
http://127.0.0.1:5000/
```
