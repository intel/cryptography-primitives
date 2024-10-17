"""
Copyright (C) 2018 Intel Corporation

SPDX-License-Identifier: MIT
"""

from PyQt5 import QtCore
from PyQt5.QtWidgets import (
    QAction,
    QActionGroup,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from tool import utils


class CustomFunctionsPanel(QWidget):
    save_script = QtCore.pyqtSignal(utils.DispatcherType)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings

        # Initializing GUI elements
        self.lib_name = QLineEdit()
        self.functions_list = QListWidget()

        # Getting default QPushButton height as QToolButton height is much less than QPushButton heigh by default
        default_button_height = QPushButton().sizeHint().height()

        # Initializing save script button (QToolButton looking as QPushButton with a menu AND with a default action)
        self.save_script_button = QToolButton()
        save_script_button_size_policy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.save_script_button.setSizePolicy(save_script_button_size_policy)
        self.save_script_button.setMinimumHeight(default_button_height)
        self.save_script_button.setPopupMode(QToolButton.MenuButtonPopup)
        self.save_script_action = QAction()
        self.save_script_action.triggered.connect(self.on_save_script)
        self.save_script_button.setDefaultAction(self.save_script_action)

        # Initializing dispatcher type actions
        self.dynamic_dispatcher_type_action = QAction("Dynamic dispatcher")
        self.dynamic_dispatcher_type_action.setCheckable(True)
        self.dynamic_dispatcher_type_action.setChecked(True)
        self.static_dispatcher_type_action = QAction("Static dispatcher")
        self.static_dispatcher_type_action.setCheckable(True)

        # Initializing dispatcher type actions group
        self.dispatcher_type_action_group = QActionGroup(self)
        self.dispatcher_type_action_group.addAction(self.dynamic_dispatcher_type_action)
        self.dispatcher_type_action_group.addAction(self.static_dispatcher_type_action)
        self.dispatcher_type_action_group.setExclusive(True)
        self.dispatcher_type_action_group.triggered.connect(self.set_save_script_button_text)
        self.set_save_script_button_text()

        # Initializing dispatcher type menu
        self.dispatcher_type_menu = QMenu()
        self.dispatcher_type_menu.addAction(self.dynamic_dispatcher_type_action)
        self.dispatcher_type_menu.addAction(self.static_dispatcher_type_action)
        self.save_script_button.setMenu(self.dispatcher_type_menu)

        # Preparing elements by giving initial values and etc
        self.lib_name.setPlaceholderText("Custom library name...")

        # Setting all widgets in their places
        layout = QVBoxLayout()
        layout.addWidget(self.lib_name)
        layout.addWidget(self.functions_list)
        layout.addWidget(self.save_script_button)
        self.setLayout(layout)

        self.settings.package_changed.connect(self.reset)

    def get_dispatcher_type(self):
        if self.dynamic_dispatcher_type_action.isChecked():
            return utils.DispatcherType.DYNAMIC
        return utils.DispatcherType.STATIC

    def set_save_script_button_text(self):
        dispatcher_type = self.get_dispatcher_type()
        dispatcher_type_text = "dynamic" if dispatcher_type == utils.DispatcherType.DYNAMIC else "static"
        save_script_button_text = f"Save build script ({dispatcher_type_text} dispatcher)"
        self.save_script_button.setText(save_script_button_text)

    def on_save_script(self):
        dispatcher_type = self.get_dispatcher_type()
        self.save_script.emit(dispatcher_type)

    def reset(self):
        self.functions_list.clear()

    def add_function(self, function):
        """
        Adds new function to required list

        :param function: name if function
        """
        self.functions_list.addItem(QListWidgetItem(function))

    def remove_function(self, function):
        """
        Removes function from left list
        """
        item = self.functions_list.findItems(function, QtCore.Qt.MatchExactly)
        if item:
            self.functions_list.takeItem(self.functions_list.row(item[0]))
