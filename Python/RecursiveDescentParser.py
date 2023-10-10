# Ade Sampson
# Phase 2.2 #
import re
import sys



if __name__ == "__main__":

    class Tree:
        def __init__(self, cargo, type, left=None, right=None):
            self.cargo = cargo
            self.left = left
            self.right = right
            self.type = type

        def __str__(self):
            return str(self.cargo)

        def print_tree_indented(self, level=0):
            if self.cargo == None:
                return
            with open(sys.argv[2], 'a') as fileOut:
                fileOut.write('        ' * level  + (self.cargo) + "\n")
            if self.left != None:
                self.left.print_tree_indented(level + 1)
            if self.type != None:
                self.type.print_tree_indented(level + 1)
            if self.right != None:
                self.right.print_tree_indented(level + 1)


    def scanner(new_input):
        token_list = []
        regex = re.compile(r'(^((if)|(then)|(else)|(endif)|(while)|(do)|(endwhile)|(skip))\s*$)'
                           r'|\d+|(([a-zA-Za-z0-9])+|[+]|[\-]|[*]|[/]|[(]|[)]|(:=)|[;]|[^\s])')
        number = re.compile(r'(\d+)')
        identifier = re.compile(r'[a-zA-Za-z0-9]+')
        punctuation = re.compile(r'[+]|[\-]|[*]|[/]|[(]|[)]|[:=]|[;]')
        keyword = re.compile(r'(^((if)|(then)|(else)|(endif)|(while)|(do)|(endwhile)|(skip))\s*)$')
        matches = regex.finditer(new_input)
        for match in matches:
            if keyword.match(match.group()):
                token_list.append("KEYWORD " + match.group())
            elif number.match(match.group()):
                token_list.append("NUMBER " + match.group())
            elif identifier.match(match.group()):
                token_list.append("IDENTIFIER " + match.group())
            elif punctuation.match(match.group()):
                token_list.append("PUNCTUATION " + match.group())

            else:
                token_list.append("ERROR READING \"" + match.group() + "\"")
        return token_list
    # since its one line, maybe have a count on the outside that iterates by one when its used
    global count
    global sList
    sList = []
    count = 0

    class parser():
        global count
        global sList
        def nextToken(self):
            if count < len(sList):
                return sList[count].split(' ')[0]
            else:
                return None
        def nextType(self):
            if count < len(sList):
                return sList[count].split(' ')[1]
            else:
                return None
        def consumeToken(self):
            global count
            count += 1
        def parseElement(self):
            if self.nextType() == '(':
                self.consumeToken()
                tree = self.parseExpression()
                if self.nextType() == ')':
                    self.consumeToken()
                else:
                    raise Exception("WOAH WOAH WOAH!!! what are you doing?")
            elif self.nextType().isdigit():
                tree = Tree ("NUMBER " + self.nextType(),None , None, None)
                self.consumeToken()

            else:
                tree = Tree("IDENTIFIER " + self.nextType(),None , None, None)
                self.consumeToken()

            return tree
        def parseExpression(self):
            tree = self.parseTerm()
            while self.nextType() == '+':
                self.consumeToken()
                tree = Tree("PUNCTUATION +",None, tree, self.parseTerm())
            return tree

        def parsePiece(self):
            tree = self.parseElement()
            while self.nextType() == '*':
                self.consumeToken()
                tree = Tree ("PUNCTUATION *", None, tree, self.parseElement())

            return tree
        def parseFactor(self):
            tree = self.parsePiece()
            while self.nextType() == '/':
                self.consumeToken()
                tree = Tree ("PUNCTUATION /",None, tree, self.parsePiece())
            return tree
        def parseTerm(self):
            tree = self.parseFactor()
            while self.nextType() == '-':
                self.consumeToken()
                tree = Tree("PUNCTUATION -",None, tree, self.parseFactor())
            return tree
        def parseStatement(self):
            tree = self.parseBaseStatement()
            while self.nextType() == ';':
                self.consumeToken()
                tree = Tree("PUNCTUATION ;",None, tree, self.parseBaseStatement())
            return tree
        def parseBaseStatement(self):
            if self.nextToken() == "IDENTIFIER":
                return self.parseAssignment()
            elif self.nextType() == "if":
                return self.parseIfStatement()
            elif self.nextType() == "while":
                return self.parseWhileStatement()
            elif self.nextType() == "skip":
                tree = Tree("skip", None, None, None)
                return tree
            else:
                raise Exception("WOAH WOAH WOAH!!! what are you doing?")

        def parseAssignment(self):
            tree = self.parseExpression()
            if self.nextType() == ":=":
                self.consumeToken()
                tree2 = self.parseExpression()
                return Tree( "PUNCTUATION :=",None, tree,tree2)
            else:
                raise Exception("WOAH WOAH WOAH!!! what are you doing?")
        def parseIfStatement(self):
            self.consumeToken()
            t1 = self.parseExpression()
            if self.nextType() == "then":
                self.consumeToken()
                t2 = self.parseStatement()
            if self.nextType() == "else":
                self.consumeToken()
                t3 = self.parseStatement()
            if self.nextType() == "endif":
                self.consumeToken()
                return Tree ("IF-STATEMENT", t2 , t1, t3)
            else:
                raise Exception("WOAH WOAH WOAH!!! what are you doing?")

        def parseWhileStatement(self):
            if self.nextType() == "while":
                self.consumeToken()
                t1 = self.parseExpression()
            if self.nextType() == "do":
                self.consumeToken()
                t2 = self.parseStatement()
            if self.nextType() == "endwhile":
                self.consumeToken()
                return Tree("WHILE-LOOP", None, t1, t2)
            else:
                raise Exception("WOAH WOAH WOAH!!! what are you doing?")

    def main():
        treeParse = Tree
        parseModule = parser()
        with open(sys.argv[1], 'r') as file:
            with open(sys.argv[2], 'a') as fileOut:
                fileOut.write("Tokens: " + '\n')
            for line in file.read().splitlines():
                try:
                    for token in scanner(line):
                        with open(sys.argv[2], 'a') as fileOut:
                            fileOut.write(token + "\n")
                            sList.append(token)
                except:
                    print("Error in line, trying next line")

        treeParse = parseModule.parseStatement()
        with open(sys.argv[2], 'a') as fileOut:
            fileOut.write("\n")
            fileOut.write("AST:" + "\n" + "\n")
        treeParse.print_tree_indented()



main()