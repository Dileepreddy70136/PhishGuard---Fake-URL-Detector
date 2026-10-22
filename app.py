from flask import Flask, jsonify, render_template, request

from detector import MAX_URL_LENGTH, analyze_url

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.get("/")
def index():
    return render_template("index.html", result=None, submitted_url="")


@app.post("/")
def check_url():
    submitted_url = request.form.get("url", "")
    try:
        result = analyze_url(submitted_url)
    except ValueError as error:
        return render_template(
            "index.html",
            result={"error": str(error)},
            submitted_url=submitted_url[:MAX_URL_LENGTH],
        ), 400

    return render_template(
        "index.html",
        result=result,
        submitted_url=submitted_url,
    )


@app.post("/api/check")
def api_check_url():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Send a JSON object with a 'url' field."}), 400

    try:
        result = analyze_url(payload.get("url"))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(result)


@app.errorhandler(413)
def request_too_large(_error):
    if request.path == "/api/check":
        return jsonify({"error": "The request body is too large."}), 413
    return render_template(
        "index.html",
        result={"error": "The submitted request is too large."},
        submitted_url="",
    ), 413


if __name__ == "__main__":
    app.run(debug=False)
