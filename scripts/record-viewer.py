import sys, gi
gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gtk, WebKit2, GLib

url, w, h = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
win = Gtk.Window()
win.set_default_size(w, h)
win.set_decorated(False)
win.move(0, 0)
view = WebKit2.WebView()
view.get_settings().set_property("enable-developer-extras", False)
def on_title(v, p):
    t = v.get_title() or 'viewer'
    win.set_title(t)
    if t == 'autoplay-done':
        GLib.timeout_add_seconds(4, Gtk.main_quit)
view.connect('notify::title', on_title)
win.add(view)
win.connect("destroy", Gtk.main_quit)
view.load_uri(url)
win.show_all()
Gtk.main()
