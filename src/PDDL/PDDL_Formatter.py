__author__ = 'Royce Mou'


class _PDDL_FormatElement(object):
    """
    Defines a base class for formatting a PDDL document.
    The first line is considered distinctly from all other lines.

    Arguments:  A sequence of strings with some identity
    Keyword Arguments:
        identity:   The identity of the arguments, e.g. type, constants
                    Value: {String}
        indentation_level:  The indentation level of all lines including the first.
                            Value: {Integer}
        subindentation_level:   The difference in indentation level between the first line and subsequent lines.
                                Note that the first line may be indented prior to the formatting given by the
                                indentation level.
                                Value: {Integer}
        display_identity:   Whether or not to display the identity of the arguments.
                            Note that if the identity is not displayed, a colon will not be printed, regardless of
                            the value of has_colon.
                            Value: {Boolean}
        parenthesize:   What to parenthesize: either nothing, the arguments, or everything.
                        Value: {'all', 'args', None}
        has_colon:  Whether or not the display the colon before the identity
                    Value: {Boolean}
        sticky: The number of arguments to "stick" to the first line.
    """
    def __init__(self, *args, **kwargs):
        self.args = args

        # TODO: 1.  A better way to redefine default parameters for subclasses is desired.
        # TODO:     Current redefinition looks up values twice and is inelegant.
        # TODO:     Keyword arguments after variable length parameters work in Python 3.
        self.identity = kwargs.get('identity', self.__class__.__name__)
        self.indentation_level = kwargs.get('indentation_level', 0)
        self.subindentation_level = kwargs.get('subindentation_level', 1)
        self.display_identity = kwargs.get('display_identity', True)
        self.parenthesize = kwargs.get('parenthesize', 'all')
        self.has_colon = kwargs.get('has_colon', True)
        self.sticky = kwargs.get('sticky', len(args))

    @staticmethod
    def _parenthesize(string):
        lplace = len(string) - len(string.lstrip())
        rplace = len(string.rstrip())
        return string[:lplace] + '(' + string[lplace:rplace] + ')' + string[rplace:]

    def __str__(self):
        indent = self.indentation_level * '\t'
        subindent = self.subindentation_level * '\t'
        newline_indent = '\n' + indent
        newline_subindent = '\n' + subindent

        sdisplay = ' '.join(map(str, self.args[:self.sticky]))
        ndisplay = ''.join((newline_subindent + '{0}').format(str(arg)) for arg in self.args[self.sticky:])
        display = sdisplay + ndisplay

        if self.parenthesize == 'args':
            display = self._parenthesize(display)

        identity = '' if not self.display_identity else self.identity if not self.has_colon else ':' + self.identity
        display = (' ' if self.sticky else '').join(filter(None, (identity, display)))

        if self.parenthesize == 'all':
            display = self._parenthesize(display)

        display = (indent if self.display_identity else '') + newline_indent.join(display.split('\n'))

        return display


class define(_PDDL_FormatElement):
    """"""
    def __init__(self, *args, **kwargs):
        super(define, self).__init__(*args, **kwargs)
        self.has_colon = kwargs.get('has_colon', False)
        self.sticky = kwargs.get('sticky', 1)


class domain(_PDDL_FormatElement):
    """"""


class requirements(_PDDL_FormatElement):
    """"""


class types(_PDDL_FormatElement):
    """"""
    class _type(_PDDL_FormatElement):
        def __init__(self, *args, **kwargs):
            super(types._type, self).__init__(*args, **kwargs)
            self.display_identity = kwargs.get('display_identity', False)
            self.parenthesize = kwargs.get('parenthesize', None)
            self.subindentation_level = kwargs.get('subindentation_level', 1)

        def __str__(self):
            if self.identity != 'type_':
                return super(types._type, self).__str__() + ' - ' + self.identity
            else:
                return self._parenthesize(super(types._type, self).__str__())

    def __init__(self, *args, **kwargs):
        super(types, self).__init__(*args, **kwargs)
        for arg in self.args:
            setattr(types, arg, type(arg, (types._type,), dict()))


class constants(_PDDL_FormatElement):
    """"""


class predicates(_PDDL_FormatElement):
    """"""

    class predicate(_PDDL_FormatElement):
        def __init__(self, *args, **kwargs):
            super(predicates.predicate, self).__init__(*args, **kwargs)
            self.display_identity = kwargs.get('display_identity', False)

    class keyword_predicate(_PDDL_FormatElement):
        def __init__(self, *args, **kwargs):
            super(predicates.keyword_predicate, self).__init__(*args, **kwargs)
            self.identity = self.identity.strip('_')
            self.display_identity = kwargs.get('display_identity', True)
            self.has_colon = kwargs.get('display_identity', False)

    class and_(keyword_predicate):
        """"""

    class not_(keyword_predicate):
        """"""

    class or_(keyword_predicate):
        """"""


class action(_PDDL_FormatElement):
    """"""

    class action_element(_PDDL_FormatElement):
        """"""
        def __init__(self, *args, **kwargs):
            super(action.action_element, self).__init__(*args, **kwargs)
            self.parenthesize = kwargs.get('parenthesize', None)

    class parameters(action_element):
        """"""
        def __init__(self, *args, **kwargs):
            super(action.parameters, self).__init__(*args, **kwargs)
            self.parenthesize = kwargs.get('parenthesize', 'args')


    class precondition(action_element):
        """"""

    class effect(action_element):
        """"""

    def __init__(self, *args, **kwargs):
        super(action, self).__init__(*args, **kwargs)
        self.sticky = kwargs.get('sticky', 1)


# Problem definitions

class problem(_PDDL_FormatElement):
    """"""
    def __init__(self, *args, **kwargs):
        super(problem, self).__init__(*args, **kwargs)
        self.has_colon = kwargs.get('has_colon', False)


class objects(_PDDL_FormatElement):
    """"""


class init(_PDDL_FormatElement):
    """"""
    def __init__(self, *args, **kwargs):
        super(init, self).__init__(*args, **kwargs)
        self.sticky = kwargs.get('sticky', 0)


class goal(_PDDL_FormatElement):
    """"""
    def __init__(self, *args, **kwargs):
        super(goal, self).__init__(*args, **kwargs)
        self.sticky = kwargs.get('sticky', 0)


# Aliases for convenience
predicate = predicates.predicate
and_ = predicates.and_
not_ = predicates.not_
or_ = predicates.or_
parameters = action.parameters
precondition = action.precondition
effect = action.effect


# Miscellaneous
def comment(string, comment_character=';'):
    return comment_character + ' ' + string + newline
newline = '\n'