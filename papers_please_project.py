import re
from datetime import datetime


class Inspector:
    def __init__(self):
        self.bulletins = []
        self.entrants = []
        self.nations_documents = {
            "Arstotzka": set(),
            "Antegria": set(),
            "Impor": set(),
            "Kolechia": set(),
            "Obristan": set(),
            "Republia": set(),
            "United Federation": set()
        }

        self.vaccinations_dict = {}

        self.current_bulletin = {
            "allowed_nations": set(),
            "required_documents": self.nations_documents,
            "required_workpass": False,
            "required_vaccinations": self.vaccinations_dict,
            "new_criminal": ""
        }

        self.our_great_nation = "Arstotzka"

        self.foreign_nations = (
            "Antegria",
            "Impor",
            "Kolechia",
            "Obristan",
            "Republia",
            "United Federation"
        )

        self.all_nations = (self.our_great_nation,) + self.foreign_nations

    def receive_bulletin(self, received_bulletin):
        """ Method that takes the bulletin given as a string and parses
        the code into data inside the inspector's dictionaries """
        self.bulletins.append(received_bulletin)
        print(self.bulletins)
        bulletin = self.current_bulletin
        vaccines = self.vaccinations_dict
        nations_documents = self.nations_documents

        documents_list = [
            'passport',
            'ID_card',
            'access_permit',
            'work_pass',
            'grant_of_asylum',
            'certificate_of_vaccination',
            'diplomatic_authorization'
        ]

        def regex(expression, string):
            """
            *args= name of the groups matched in the expression

            ex. expression = (Allow citizens of)(?P<nations>.+)
                arg = 'nations'
            """
            regex_compiler = re.compile(expression)
            matches = re.findall(regex_compiler, string)
            return matches

        def allow_and_deny_nations():
            """ Checks the bulletin for allowed and denied nations
                    and adds them to self.current_bulletin """
            matched_allowed_list = regex(
                '(?:Allow citizens of )(?P<nations>.+)',
                received_bulletin)
            matched_denied_list = regex(
                '(?:Deny citizens of)(?P<nations>.+)',
                received_bulletin)

            def add_or_discard_nations(matched_list,
                                       add=False,
                                       discard=False):
                if matched_list:
                    for match in matched_list:
                        found_nations = match.split(',')
                        for nation in found_nations:
                            if add:
                                bulletin['allowed_nations'].add(nation.strip())
                            if discard:
                                bulletin['allowed_nations'].discard(nation.strip())

            add_or_discard_nations(matched_allowed_list,
                                   add=True)
            add_or_discard_nations(matched_denied_list,
                                   discard=True)

        def add_and_remove_documents():
            """ Checks the bulletin for required/ no longer
            required documents and adds them to self.documents_dict """

            def name_to_var(doc):
                """ eg. Turns "ID Card" into "id_card" """
                return '_'.join(doc.split())

            def is_work_pass_requirement():
                """ eg. if "Workers require work pass" phrase is
                in the bulletin adds the information to self.documents_dict """
                if regex('(Workers require work pass)',
                         received_bulletin):
                    return True

                if regex('(Workers no longer require work pass)',
                         received_bulletin):
                    return False
                return

            def add_docs_needed_by_entrants(nations_documents_dict):
                """ Checks the bulletin for "Entrants require <document>" and
                adds all nations to self.nations_documents dict """
                matched_list = regex(
                    '(?:Entrants require )(?P<document>.+)',
                    received_bulletin)
                if matched_list:
                    for match in matched_list:
                        req_document = name_to_var(match)
                        if req_document in documents_list:
                            for nation in self.all_nations:
                                nations_documents_dict[nation].add(req_document)

            def add_docs_needed_by_foreigners(nations_documents_dict):
                """ Checks the bulletin for "Foreigners require <document>" and
                adds the foreign countries (all besides Arstotzka)
                to nations_documents"""
                matched_list = regex(
                    '(?:Foreigners require )(?P<document>.+)',
                    received_bulletin)
                if matched_list:
                    for match in matched_list:
                        req_document = name_to_var(match)
                        if req_document in documents_list:
                            for nation in self.foreign_nations:
                                nations_documents_dict[nation].add(req_document)

            def add_docs_needed_by_specific_nations(nations_documents_dict):
                """ Checks the bulletin for "Citizens of <nation> require <document>"
                and adds the information to nations_documents"""
                matched_list = regex(
                    '(?:Citizens of )(?P<nations>.+)(?: require )(?P<document>.+)',
                    received_bulletin)
                if matched_list:
                    for match in matched_list:
                        nations = match[0].split(',')
                        req_document = name_to_var(match[1])
                        if req_document in documents_list:
                            for nation in nations:
                                nations_documents_dict[nation.strip()].add(req_document)

            if is_work_pass_requirement() == True:
                bulletin["required_workpass"] = True

            if is_work_pass_requirement() == False:
                bulletin["required_workpass"] = False

            add_docs_needed_by_entrants(nations_documents)

            add_docs_needed_by_foreigners(nations_documents)

            add_docs_needed_by_specific_nations(nations_documents)

        def add_and_remove_vaccinations():

            def check_for_vac_needed_by_entrants():
                """ Checks the bulletin for "Entrants require <vaccine>"
                and adds the data to the global dictionary """
                matched_list = regex(
                    '(?:Entrants require )(?P<vaccine>.+)(?<!certificate of)(?: vaccination)',
                    received_bulletin)

                if matched_list:
                    for match in matched_list:
                        req_vaccine = match
                        vaccines[req_vaccine] = set(self.all_nations)

                matched_list = regex(
                    '(?:Entrants no longer require )(?P<vaccine>.+)(?: vaccination)',
                    received_bulletin)

                if matched_list:
                    for match in matched_list:
                        not_req_vaccine = match
                        del vaccines[not_req_vaccine]

            def check_for_vac_needed_by_foreigners():
                """ Checks the bulletin for "Foreigners require <vaccine>"
                and adds the data to the global dictionary """
                matched_list = regex(
                    '(?:Foreigners require )(?P<vaccine>.+)(?: vaccination)',
                    received_bulletin)

                if matched_list:
                    for match in matched_list:
                        req_vaccine = match
                        if req_vaccine in vaccines:
                            vaccines[req_vaccine].update(set(self.foreign_nations))
                        else:
                            vaccines[req_vaccine] = set(self.foreign_nations)

                matched_list = regex(
                    '(?:Foreigners no longer require )(?P<vaccine>.+)(?: vaccination)',
                    received_bulletin)

                if matched_list:
                    for match in matched_list:
                        not_req_vaccine = match
                        vaccines[not_req_vaccine] = \
                            {x for x in vaccines[not_req_vaccine]
                             if x not in list(self.foreign_nations)}

                        if vaccines[not_req_vaccine] == set():
                            del vaccines[not_req_vaccine]

            def check_for_vac_needed_by_specific_nations():
                """ Checks the bulletin for "Citizens of <nation> require <vaccine>"
                and adds the data to the global dictionary """
                matched_list = regex(
                    '(?:Citizens of )(?P<nations>.+)(?<!no longer)(?: require )(?P<vaccine>.+)(?: vaccination)',
                    received_bulletin)

                if matched_list:

                    for match in matched_list:
                        nations = match[0].split(',')
                        req_vaccine = match[1]

                        if req_vaccine not in vaccines:
                            vaccines[req_vaccine] = set()

                        for nation in nations:
                            if nation.strip() in self.all_nations:
                                vaccines[req_vaccine].add(nation.strip())

                matched_list = regex(
                    '(?:Citizens of )(?P<nations>.+)(?: no longer require )(?P<vaccine>.+)(?: vaccination)',
                    received_bulletin)

                if matched_list:
                    for match in matched_list:
                        nations = match[0].split(',')
                        not_req_vaccine = match[1]

                        for nation in nations:
                            vaccines[not_req_vaccine].discard(nation.strip())

                        if vaccines[not_req_vaccine] == set():
                            del vaccines[not_req_vaccine]

            check_for_vac_needed_by_entrants()

            check_for_vac_needed_by_foreigners()

            check_for_vac_needed_by_specific_nations()

        def add_new_criminal():
            matched_list = regex('(?:Wanted by the State: )(?P<criminal>.+)',
                                 received_bulletin)
            if matched_list:
                new_criminal = matched_list[0]

                bulletin['new_criminal'] = new_criminal

        allow_and_deny_nations()

        add_and_remove_documents()

        add_and_remove_vaccinations()

        add_new_criminal()

    def inspect(self, entrant):
        """ Method that takes an entrant in the form of a dictionary and checks
        if there is mismatching information, missing documents,
        missing vaccines, expired documents or if the entrant is a criminal """

        bulletin = self.current_bulletin
        vaccines = self.vaccinations_dict
        required_documents = self.nations_documents

        def doc_var_to_name(doc_var):
            """ eg. Turns "id_card" into "id card" """
            return doc_var.replace("_", " ")

        def regex(expression, string, *args):
            """
            *args= name of the groups matched in the expression

            ex. expression = (Allow citizens of)(?P<nations>.+)
                arg = 'nations'
            """
            regex_compiler = re.compile(expression)
            match = re.search(regex_compiler, string)
            groups = []

            if match:
                if args:
                    for arg in args:
                        groups.append(match.group(arg))
                    return groups
                return True
            return False

        def check_mismatching_information():

            def is_mismatching_information(types):
                # types = 'ids', 'names', 'nations', 'dob'(date of birth)

                regex_dict = {
                    'ids': ('(ID#: )(?P<id>.+)', 'id'),
                    'names': ('(NAME: )(?P<name>.+)', 'name'),
                    'nations': ('(NATION: )(?P<nation>.+)', 'nation'),
                    'dob': ('(DOB: )(?P<dob>.+)', 'dob')
                }

                doc_type = regex_dict[types][0]
                regex_expression = regex_dict[types][1]

                appearing_info = set()

                for value in entrant.values():
                    matched_list = regex(doc_type,
                                         value,
                                         regex_expression)
                    if matched_list:
                        appearing_info.add(matched_list[0])
                        if len(appearing_info) > 1:
                            return True
                return False

            if is_mismatching_information('ids'):
                return "Detainment: ID number mismatch."

            if is_mismatching_information('names'):
                return "Detainment: name mismatch."

            if is_mismatching_information('nations'):
                return "Detainment: nationality mismatch."

            if is_mismatching_information('dob'):
                return "Detainment: date of birth mismatch."

            return

        def check_missing_documents(nation):
            if not entrant:
                return "Entry denied: missing required passport."

            if is_vac_in_dict(vaccines, entrants_nation):
                if "certificate_of_vaccination" not in entrant:
                    return "Entry denied: missing required certificate of vaccination."

            entrants_docs = list(entrant)

            def has_document(document):
                if document in entrants_docs:
                    return True
                return False

            def is_authorization_valid():
                matched_list = regex('(ACCESS: )(?P<nations>.+)',
                                     entrant['diplomatic_authorization'],
                                     'nations')
                if matched_list:
                    for nation in matched_list[0].split(","):
                        if nation.strip() == "Arstotzka":
                            return True
                return False

            def check_for_workpass():
                if 'access_permit' in entrant:
                    if bulletin["required_workpass"] == True \
                            and regex('(PURPOSE: WORK)',
                                      entrant['access_permit']):
                        if "work_pass" not in entrant:
                            return "Entry denied: missing required work pass."
                return

            for document in required_documents[nation]:
                if document == 'access_permit':
                    if has_document("access_permit"):
                        continue
                    elif has_document("grant_of_asylum"):
                        continue
                    elif has_document("diplomatic_authorization"):
                        if is_authorization_valid():
                            continue
                        return "Entry denied: invalid diplomatic authorization."

                    return "Entry denied: missing required access permit."

                if has_document(document):
                    continue
                else:
                    return "Entry denied: missing required " \
                           + doc_var_to_name(document) + "."

            if check_for_workpass():
                return check_for_workpass()

            return

        def is_vac_in_dict(my_dict, lookup):
            for value in my_dict.values():
                for x in value:
                    if lookup in x:
                        return True
            return False

        def check_missing_vaccines():

            if "certificate_of_vaccination" in entrant:
                for vaccine in vaccines:
                    if entrants_nation in vaccines[vaccine] \
                            and vaccine not in entrant["certificate_of_vaccination"]:
                        return "Entry denied: missing required vaccination."
            return

        def check_documents_expiration():

            def is_document_expired(document):
                exp_date = datetime(1982, 11, 22)

                try:
                    date_str = ''.join(
                        regex('(EXP: )(?P<date>.+)', entrant[document], 'date'))

                    date = datetime.strptime(date_str, '%Y.%m.%d')
                    if date <= exp_date:
                        return True
                    return False

                except TypeError:
                    return False

            for document in entrant:
                if is_document_expired(document):
                    return "Entry denied: " + doc_var_to_name(
                        str(document)) + " expired."
            return

        def check_criminal(document):
            matched_list = regex('(NAME: )(?P<name>.+)',
                                 document,
                                 'name')
            if matched_list:
                name = ' '.join(reversed(matched_list[0].replace(",", "").split(" ")))

                if bulletin['new_criminal'] == name:
                    return "Detainment: Entrant is a wanted criminal."
            return

        if check_mismatching_information():
            return check_mismatching_information()

        for document in entrant.values():
            if check_criminal(document):
                return check_criminal(document)

        if check_documents_expiration():
            return check_documents_expiration()

        def returns_entrants_nation(entrant):
            for value in entrant.values():
                matched_list = regex('(NATION: )(?P<nation>.+)',
                                     value,
                                     'nation')
                if matched_list:
                    return matched_list[0]
            return

        entrants_nation = returns_entrants_nation(entrant)

        if not entrants_nation:
            list_of_values = list(required_documents.values())
            for i in range(len(list_of_values)):
                list_of_values[i] = list(list_of_values[i])
            result = ''.join(set(list_of_values[0]).intersection(*list_of_values))

            return "Entry denied: missing required " + result + "."

        if check_missing_documents(entrants_nation):
            return check_missing_documents(entrants_nation)

        if check_missing_vaccines():
            return check_missing_vaccines()

        if entrants_nation not in bulletin['allowed_nations']:
            return "Entry denied: citizen of banned nation."

        if entrants_nation == "Arstotzka":
            return "Glory to Arstotzka."
        return "Cause no trouble."
