from flask import Blueprint, render_template

ui_bp = Blueprint("ui", __name__)


@ui_bp.get("/")
def index():
    return render_template("demo.html")


@ui_bp.get("/demo")
def demo():
    return render_template("demo.html")
