
# inspired by this gist of Willi Ballenthin
# https://gist.github.com/williballenthin/277eedca569043ef0984


def get_QtCore():
    try:
        # IDA 6.8 and below
        import PySide.QtCore as QtCore
        return QtCore
    except ImportError:
        # IDA 6.9
        import PyQt5.QtCore as QtCore
        return QtCore


def get_QtGui():
    try:
        import PySide.QtGui as QtGui
        return QtGui
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui


def get_QtWidgets():
    try:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets
    except ImportError:
        return None


def get_QTreeWidget():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidget
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidget


def get_QTreeWidgetItem():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidgetItem
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidgetItem


def get_QTableWidgetItem():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidgetItem
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem


def get_QIcon():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QIcon
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui.QIcon


def get_QWidget():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QWidget
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QWidget


def get_QVBoxLayout():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QVBoxLayout
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QVBoxLayout


def get_QHBoxLayout():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QHBoxLayout
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QHBoxLayout


def get_QSplitter():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QSplitter
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSplitter


def get_QStyleFactory():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QStyleFactory
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleFactory


def get_QStyleOptionSlider():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QStyleOptionSlider
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleOptionSlider


def get_QApplication():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QApplication
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QApplication


def get_QPainter():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QPainter
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui.QPainter


def get_DescendingOrder():
    try:
        import PySide.QtCore as QtCore
        return QtCore.Qt.SortOrder.DescendingOrder
    except ImportError:
        import PyQt5.QtCore as QtCore
        return QtCore.Qt.DescendingOrder


def get_QTabWidget():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QTabWidget
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTabWidget


def get_QStyle():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QStyle
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyle


def get_QLabel():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QLabel
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLabel


def get_QTableWidget():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidget
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidget


def get_QTableWidgetItem():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidgetItem
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem


def get_QPushButton():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QPushButton
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QPushButton


def get_QAbstractItemView():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QAbstractItemView
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAbstractItemView


def get_QScrollArea():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QScrollArea
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QScrollArea


def get_QSizePolicy():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QSizePolicy
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSizePolicy


def get_QLineEdit():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QLineEdit
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLineEdit


def get_QCompleter():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QCompleter
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCompleter


def get_QTextBrowser():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QTextBrowser
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextBrowser


def get_QSlider():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QSlider
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSlider


def get_QMainWindow():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QMainWindow
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QMainWindow


def get_QTextEdit():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QTextEdit
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextEdit


def get_QDialog():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QDialog
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QDialog


def get_QGroupBox():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QGroupBox
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QGroupBox


def get_QRadioButton():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QRadioButton
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QRadioButton


def get_QComboBox():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QComboBox
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QComboBox


def get_QCheckBox():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QCheckBox
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCheckBox


def get_QAction():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QAction
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAction


def get_QBrush():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QBrush
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui.QBrush


def get_QColor():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QColor
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui.QColor


def get_QStringListModel():
    try:
        import PySide.QtGui as QtGui
        return QtGui.QStringListModel
    except ImportError:
        import PyQt5.QtCore as QtCore
        return QtCore.QStringListModel


def get_Signal():
    try:
        import PySide.QtCore as QtCore
        return QtCore.Signal
    except ImportError:
        import PyQt5.QtCore as QtCore
        return QtCore.pyqtSignal
