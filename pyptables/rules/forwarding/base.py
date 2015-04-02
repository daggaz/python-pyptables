from pyptables.rules import Accept, Drop, AbstractRule, Rule, Reject

class ForwardingRule(AbstractRule):
    """This class represents an iptables rule for forwarding
    packets from one location to another.
    """
    
    def __init__(self, policy, sources, destinations, channels=[], log=False, log_id=None, log_cls=None, comment=None, args=None):
        """Creates a ForwardingRule
           
        policy       - the action to take (ACCEPT, DROP, REJECT, etc.) on matching the rule
        sources      - the source location(s) to match
        destinations - the destination location(s) to match
        channels     - the channel(s) to match
        log          - boolean indicated if "hits" on this rule should be logged
        comment      - a comment for the rule
        args         - list of ArgumentLists of additional arguments to match
        """
        super(ForwardingRule, self).__init__(comment)
        self.policy = policy
        self.sources = list(sources)
        self.destinations = list(destinations)
        self.channels = list(channels)
        self.log = log
        self.log_id = log_id
        self.log_cls = log_cls
        self.args = args
    
    def rule_definitions(self):
        """Generate the iptables rules for this rule"""
        result = []
        for rule in self._rules():
            result.extend(rule.rule_definitions())
        return result
    
    def _base_rules(self):
        rules = []
        if self.log:
            rules.append(self.log_cls(prefix='FWD %s %s' % (self.log_id, self.policy.upper()[0]),
                                      comment=self.comment,
                                      ))
        
        if self.policy.upper() == Rule.ACCEPT:
            rules.append(Accept(comment=self.comment))
        elif self.policy.upper() == Rule.DROP:
            rules.append(Drop(comment=self.comment))
        elif self.policy.upper() == Rule.REJECT:
            rules.append(Reject(comment=self.comment))
        elif self.policy.upper() == Rule.NONE:
            pass
        else:
            raise ValueError('policy must be either %s, %s, %s or %s' % (Rule.ACCEPT, Rule.DROP, Rule.REJECT, Rule.NONE))
        
        return rules
    
    def _rules(self):
        rules = self._base_rules()
        rules = self._add_routes(rules)
        rules = self._add_channels(rules)
        rules = self._add_args(rules)
        return rules
    
    def _add_routes(self, rules):
        if not (self.sources or self.destinations):
            return rules
        
        result = []
        for rule in rules:
            if not self.sources:
                for destination in self.destinations:
                    result.append(rule(args=(destination.as_output(),),
                                       comment="%s: route any -> %s" % (rule.comment,
                                                                        destination,
                                                                        ),
                                       ))
            elif not self.destinations:
                for source in self.sources:
                    result.append(rule(args=(source.as_input(),),
                                       comment="%s: route %s -> any" % (rule.comment,
                                                                        source,
                                                                        ),
                                       ))
            else:
                for source in self.sources:
                    for destination in self.destinations:
                        result.append(rule(args=(source.as_input(), destination.as_output()),
                                           comment="%s: route %s -> %s" % (rule.comment,
                                                                          source,
                                                                          destination,
                                                                          ),
                                           ))
        return result
    
    def _add_channels(self, rules):
        if not self.channels:
            return rules
        result = []
        for rule in rules:
            for channel in self.channels:
                result.append(rule(args=[channel],
                                   comment="%s, channel %s" % (rule.comment, channel),
                                   ))
        return result

    def _add_args(self, rules):
        if not self.args:
            return rules
        result = []
        for rule in rules:
            result.append(rule(args=self.args,
                               comment="%s, plus %s" % (rule.comment,
                                                        ", ".join(map(str, self.args)),
                                                        ),
                               ))
        return result

