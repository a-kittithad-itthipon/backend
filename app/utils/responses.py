from flask import jsonify


def success(message: str, data: dict, status: int):
    return jsonify({
        'success': True,
        'message': message,
        'data': data
    }), status


def error(message: str, error_code: str, status: int):
    return jsonify({
        'success': False,
        'message': message,
        'error': {
            'code': error_code
        }
    }), status
