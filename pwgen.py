#!/usr/bin/env python3
#encoding: utf-8
#
#               Copyright(C) Hans Alves, 2012.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import hashlib
import string
import os.path
from optparse import OptionParser

letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
digits = '0123456789'
punctuation = '!#$%&\'()*+,-./:;<=>?@[\\]^_{|}~'

def generate(master, reason, length=16, punctuation_allowed=False):
    characters = letters + digits + \
                (punctuation_allowed and punctuation or '')
    hash = hashlib.sha512()
    len_to_go = length
    pwd = ''
    while len_to_go:
        hash.update(master.encode())
        hash.update(reason.encode())
        hexdigest = hash.hexdigest()
        binary_pass = [int(hexdigest[i:i+2], 16)
                        for i in range(0, len(hexdigest), 2)]
        pwd_part = ''.join([characters[int(i / 256.0 * len(characters))]
                            for i in binary_pass])[0:len_to_go]
        len_to_go -= len(pwd_part)
        pwd += pwd_part
    return pwd

def main_console(options):
    import getpass
    mpw1 = 'spam'
    mpw2 = 'eggs'
    while mpw1 != mpw2:
        mpw1 = getpass.getpass('master password:')
        if options.unsafe:
            mpw2 = mpw1
        else:
            mpw2 = getpass.getpass('retype master password:')
        if mpw1 != mpw2:
            print('passwords do not match, please try again.')
    import readline
    reason = input('reason:')
    length = ''
    while not isinstance(length, int):
        length = input('length (16):')
        if length == '':
            length = 16
        else:
            try:
                length = int(length)
            except ValueError:
                print('Invalid Length, please enter a number')
    punc = input('use punctuation [Y/N]:')
    punctuation_allowed = punc.lower() in ('y', 'yes')
    print('password:', end='')
    print(generate(mpw1, reason, length, punctuation_allowed),
          file=sys.stderr)

def define_gui(tkinter):
    # do this in a function so the gui version doesn't crash when used
    # on a system without tkinter intstalled
    class Application(tkinter.Frame):
        def __init__(self, master, options):
            tkinter.Frame.__init__(self, master)
            self.master = master
            self.options = options
            self.showing = False
            self.use_punctuation = tkinter.IntVar()
            self.rfile = os.path.expanduser(os.path.join('~', '.pwgen'))
            if os.path.exists(self.rfile):
                self.reasons = set([l.strip()
                                    for l in
                                    open(self.rfile, 'r').readlines()])
            else:
                self.reasons = set()
            self.createwidgets()
            self.master.bind('<Control-s>', lambda e: self.showpwd())
            self.master.bind('<Control-c>', lambda e: self.copypwd())
            self.master.bind('<Control-r>', lambda e: self.reason.focus_set())
            self.pack()
            self.mpw1.focus_set()



        def createwidgets(self):
            row = 0
            self.mpw1label = tkinter.ttk.Label(self)
            self.mpw1label['text'] = 'The master password:'
            self.mpw1 = tkinter.ttk.Entry(self)
            self.mpw1['show'] = '*'
            self.mpw1label.grid(column=0, row=row,
                                sticky='w', pady=3, padx=3)
            self.mpw1.grid(column=1, row=row, sticky='w', pady=3)
            row += 1

            if not self.options.unsafe:
                self.mpw2label = tkinter.ttk.Label(self)
                self.mpw2label['text'] = 'Retype master password:'
                self.mpw2 = tkinter.ttk.Entry(self)
                self.mpw2['show'] = '*'
                self.mpw2label.grid(column=0, row=row,
                                    sticky='w', pady=3, padx=3)
                self.mpw2.grid(column=1, row=row, sticky='w', pady=3)
                row += 1

            self.reasonlabel = tkinter.ttk.Label(self)
            self.reasonlabel['text'] = 'The reason:'
            self.reason = tkinter.ttk.Combobox(self)
            self.reason['values'] = sorted(self.reasons)
            self.reasonlabel.grid(column=0, row=row,
                                  sticky='w', pady=3, padx=3)
            self.reason.grid(column=1, row=row, sticky='w', pady=3)
            row += 1

            self.lengthlabel = tkinter.ttk.Label(self)
            self.lengthlabel['text'] = 'The password size:'
            self.length = tkinter.ttk.Entry(self)
            self.length.insert(tkinter.END, '16')
            self.lengthlabel.grid(column=0, row=row,
                                  sticky='w', pady=3, padx=3)
            self.length.grid(column=1, row=row, sticky='w', pady=3)
            row += 1

            self.punctuation = tkinter.ttk.Checkbutton(self,
                                    variable=self.use_punctuation)
            self.punctuation['text'] = 'Use punctuation characters'
            self.punctuation.grid(column=0, columnspan=2, row=row,
                                  pady=3, padx=3)
            row += 1

            self.showbutton = tkinter.ttk.Button(self)
            self.showbutton['text'] = 'Show password'
            self.showbutton['command'] = self.showpwd
            self.copybutton = tkinter.ttk.Button(self)
            self.copybutton['text'] = 'Copy password to clipboard'
            self.copybutton['command'] = self.copypwd
            self.showbutton.grid(column=0, row=row, pady=3)
            self.copybutton.grid(column=1, row=row, pady=3)
            row += 1

            self.pwlabel = tkinter.ttk.Label(self)
            self.pwlabel['text'] = 'password'
            self.pwlabel.grid(columnspan=2, row=row, pady=10)

        def generate(self):
            pwd = None
            try:
                length = int(self.length.get())
            except ValueError:
                self.pwlabel['text'] = \
                    'Length is not a number'
                self.showing = False
                return
            if self.options.unsafe or \
               self.mpw1.get() == self.mpw2.get():
                reason = self.reason.get().strip()
                if reason not in self.reasons:
                    self.reasons.add(reason)
                    open(self.rfile, 'a').write(reason + '\n')
                    self.reason['values'] = sorted(self.reasons)
                pwd = generate(self.mpw1.get(),
                               reason,
                               length,
                               self.use_punctuation.get() == 1 and \
                               True or False)
                self.pwlabel['text'] = 'password'
            else:
                self.pwlabel['text'] = \
                    'Wrong password, please try again.'
                self.showing = False
            return pwd

        def showpwd(self):
            if self.showing:
                self.pwlabel['text'] = 'password'
                self.showbutton['text'] = 'Show password'
                self.showing = False
            else:
                pwd = self.generate()
                if pwd is not None:
                    self.showbutton['text'] = 'Clear password'
                    self.pwlabel['text'] = pwd
                    self.showing = True

        def copypwd(self):
            pwd = self.generate()
            if pwd is not None:
                self.master.clipboard_clear()
                self.master.clipboard_append(pwd)

    return Application


def main_gui(options):
    import tkinter
    import tkinter.ttk
    Application = define_gui(tkinter)
    root = tkinter.Tk()
    root.title(sys.argv[0].split('/')[-1])
    app = Application(root, options)
    app.mainloop()

def main():
    parser = OptionParser(usage='%prog [options]',
                          version='pwgen.py 2.1')
    parser.add_option('-c', '--console', dest='console', default=False,
                      action='store_true', help="Don't open the GUI")
    parser.add_option('-u', '--unsafe', dest='unsafe', default=False,
                      action='store_true',
                      help="Don't ask to confirm the master-password")
    options, arguments = parser.parse_args()
    if options.console:
        main_console(options)
    else:
        main_gui(options)

if __name__ == '__main__':
    main()
