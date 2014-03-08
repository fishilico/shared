/**
 * Create a semi-transparent window with Gtk+
 * 
 * Original source code from:
 * http://stackoverflow.com/questions/3908565/how-to-make-gtk-window-background-transparent
 */
#include <gtk/gtk.h>
#include <gdk/gdkscreen.h>
#include <cairo.h>

static void screen_changed(GtkWidget *widget, GdkScreen *old_screen, gpointer user_data);
static gboolean expose(GtkWidget *widget, GdkEventExpose *event, gpointer user_data);
static void clicked(GtkWindow *win, GdkEventButton *event, gpointer user_data);

int main(int argc, char **argv)
{
    GtkWidget *window, *fixed_container, *label;

    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 400);
    gtk_window_set_title(GTK_WINDOW(window), "Alpha Window Demo");
    g_signal_connect(G_OBJECT(window), "delete-event", gtk_main_quit, NULL);

    gtk_widget_set_app_paintable(window, TRUE);

#if GTK_CHECK_VERSION (3, 0, 0)
    g_signal_connect(G_OBJECT(window), "draw", G_CALLBACK(expose), NULL);
#else
    g_signal_connect(G_OBJECT(window), "expose-event", G_CALLBACK(expose), NULL);
#endif
    g_signal_connect(G_OBJECT(window), "screen-changed", G_CALLBACK(screen_changed), NULL);

    gtk_window_set_decorated(GTK_WINDOW(window), TRUE);
    gtk_widget_add_events(window, GDK_BUTTON_PRESS_MASK);
    g_signal_connect(G_OBJECT(window), "button-press-event", G_CALLBACK(clicked), NULL);

    fixed_container = gtk_fixed_new();
    gtk_container_add(GTK_CONTAINER(window), fixed_container);
    label = gtk_label_new("Click in the window to toggle decoration.");
    gtk_container_add(GTK_CONTAINER(fixed_container), label);

    screen_changed(window, NULL, NULL);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}

gboolean supports_alpha = FALSE;
static void screen_changed(
    GtkWidget *widget,
    GdkScreen *old_screen __attribute__ ((unused)),
    gpointer userdata __attribute__ ((unused)))
{
    GdkScreen *screen;

#if GTK_CHECK_VERSION(3, 0, 0)
    GdkVisual *visual;
    int depth;

    /* To check if the display supports alpha channels, get the visual */
    screen = gtk_widget_get_screen(widget);
    visual = gdk_screen_get_rgba_visual(screen);
    if (!visual) {
        printf("Unable to get a visual associated to your screen\n");
        supports_alpha = FALSE;
        return;
    }
    depth = gdk_visual_get_depth(visual);
    supports_alpha = (depth == 32);
    if (supports_alpha) {
        printf("Your screen supports alpha channels (color depth %d)\n", depth);
    } else {
        printf("Your screen does not support alpha channels (color depth %d)\n", depth);
    }
    gtk_widget_set_visual(widget, visual);
#else
    GdkColormap *colormap;

    /* To check if the display supports alpha channels, get the colormap */
    screen = gtk_widget_get_screen(widget);
    colormap = gdk_screen_get_rgba_colormap(screen);
    if (!colormap) {
        printf("Your screen does not support alpha channels\n");
        colormap = gdk_screen_get_rgb_colormap(screen);
        supports_alpha = FALSE;
    } else {
        printf("Your screen supports alpha channels\n");
        supports_alpha = TRUE;
    }
    gtk_widget_set_colormap(widget, colormap);
#endif
}

static gboolean expose(
    GtkWidget *widget,
    GdkEventExpose *event __attribute__ ((unused)),
    gpointer userdata __attribute__ ((unused)))
{
    GdkWindow *window;
    cairo_t *cr;

    window = gtk_widget_get_window(widget);
    cr = gdk_cairo_create(window);

    /* Select white color, semi-transparent if alpha is supported */
    if (supports_alpha) {
        cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.5);
    } else {
        cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    }

    /* Draw the background */
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_paint(cr);

    cairo_destroy(cr);
    return FALSE;
}

static void clicked(
    GtkWindow *win,
    GdkEventButton *event __attribute__ ((unused)),
    gpointer user_data __attribute__ ((unused)))
{
    /* toggle window manager frames */
    gtk_window_set_decorated(win, !gtk_window_get_decorated(win));
}
