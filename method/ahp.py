import pandas
from flask import jsonify

# Random Consistency Index
# Call it by RANDOM_CONSISTENCY_INDEX[total_criteria - 1]
RANDOM_CONSISTENCY_INDEX = [0, 0, 0.58, 0.90, 1.12, 1.24, 1.32, 1.41, 1.45, 1.49] # RI of 1 - 10

""" 
Importance Value Passed will update 2 criteria importance passed
"""
def update_importance(criteria_a, criteria_b, importance):
    criteria_a.importance.update({criteria_b.name: importance})
    criteria_b.importance.update({criteria_a.name: 1/importance})

""" 
Check the Consistency Ratio
False: CI >= 0.1
True: CI < 0.1
"""
def calculate_consistency_ratio(criteria_list, comparison_matrix, normalization_matrix):
    sum_eigen_value = 0
    for index in range(len(criteria_list)):
        sum_eigen_value += normalization_matrix.iloc[index]['Priority'] * comparison_matrix[criteria_list[index]].sum(axis=0)
    consistency_index = (sum_eigen_value - len(criteria_list)) / (len(criteria_list) - 1)
    result = { 
        'status': False, 
        'CR': consistency_index / RANDOM_CONSISTENCY_INDEX[len(criteria_list)-1] 
    }
    if result['CR'] < 0.1:
        result['status'] = True
    return result

""" 
This will create make the criterias/crips value passed and give it priority value
Return criteria list if it passed the concistency ratio criteria
Return False if it failed the consistency ratio criteria
"""
def calculate_priority(criteria_list, criterias):
    # Make Comparison Matrix
    comparison_matrix = {}
    num = 0
    for index in range(len(criteria_list)):
        n_list = []
        for c in criteria_list:
            n_list.append(criterias[index].importance[c])
        comparison_matrix.update({criteria_list[index]: n_list})
        num += 1

    cm = pandas.DataFrame(data=comparison_matrix, index=criteria_list).T

    normalization_matrix = {}
    num = 0
    for index in range(len(criteria_list)):
        n_list = []
        for c in criteria_list:
            n_list.append(cm.iloc[index][c]/cm[c].sum(axis=0))
        normalization_matrix.update({criteria_list[index]: n_list})
        num += 1

    nm = pandas.DataFrame(data=normalization_matrix, index=criteria_list).T
    nm['Total'] = nm.sum(axis=1, numeric_only=True)
    num = 0
    priority_list = []
    for index in range(len(criteria_list)):
        priority_list.append(nm.iloc[index]['Total']/len(criteria_list))
    nm['Priority'] = priority_list
    cr = calculate_consistency_ratio(criteria_list=criteria_list, comparison_matrix=cm, normalization_matrix=nm)
    num = 0
    for c in criterias:
        c.update_priority(nm.iloc[num]['Priority'])
        print('C:{}, Prority:{}'.format(c.name, c.priority))
        num += 1
    print('====================================')
    print('====================================')
    if cr['status'] is False:
        return {'status': False, 'CR': cr['CR']}
    return {'status': True, 'criterias': criterias}

""" 
CLASS FOR CRISP
"""
class AHP_Crisp():
    def __init__(self, name, details, criteria_list):
        self.name = name
        self.detail = details
        self.priority = 0.00
        self.importance = {}
        # Input all of the criteria names into the importance variable
        for c in criteria_list:
            self.importance.update({c: 0}) # Init value
        self.importance.update({name: 1})

    def update_priority(self, priority):
        self.priority = round(priority, 5)
    
    def __str__(self):
        return f"name={self.name}, details={self.detail}, importance={self.importance}"
    
""" 
CLASS FOR CRITERIA
"""
class AHP_Criteria():
    # Criteria Type
    __number = 0
    __string = 1
    # Number Criteria Type
    __equals_to = 0
    __more_than_equal = 1
    __more_than = 2
    __less_than_equal = 3
    __less_than = 4
    __in_between_inclusive = 5
    __in_between = 6

    def __init__(self, name, crisp_type, criteria_list):
        self.name = name
        self.crisp_type = crisp_type # value is 0 or 1
        self.priority = 0.00
        self.importance = {}
        # Input all of the criteria names into the importance variable
        for c in criteria_list:
            self.importance.update({c: 0}) # Init value
        self.importance.update({name: 1})

    def update_priority(self, priority):
        self.priority = round(priority, 5)
    
    def update_crisps(self, crisps):
        self.crisps = crisps

    """ 
    CRITERIA PROCESSS FUNCTIONS
    """
    # Process the Row Value Given with this Criteria
    def get_importance_final_value(self, rowValue):
        crisp_priority_value = self.check_crisp_type(rowValue)
        return round(crisp_priority_value * self.priority, 5)
    
    # Check Criteria Type
    def check_crisp_type(self, rowValue):
        if self.crisp_type == self.__number:
            return self.number_criteria(rowValue)
        elif self.crisp_type == self.__string:
            return self.string_criteria(rowValue)
        else:
            return jsonify(msg="Something went wrong when Processing Criteria")
    
    """ 
    NUMBER CRISP TYPE
    """
    def check_expression(self,value,expression,comparator):
        return eval('x'+expression+'m',{},{'x':value,'m':comparator[0]})
    
    def check_in_between_inclusive(self, value, comparator):
        return eval('c0 <= v <= c1',{}, {'c0':comparator[0], 'v':value, 'c1': comparator[1]})
    
    def check_in_between(self, value, comparator):
        return eval('c0 < v < c1',{}, {'c0':comparator[0], 'v':value, 'c1': comparator[1]})
        
    def check_expression_value(self, value, expression, comparator):
        if expression==self.__equals_to:
            return self.check_expression(value, "==", comparator)
        elif expression==self.__more_than_equal:
            return self.check_expression(value, ">=", comparator)
        elif expression==self.__more_than:
            return self.check_expression(value, ">", comparator)
        elif expression==self.__less_than_equal:
            return self.check_expression(value, "<=", comparator)
        elif expression==self.__less_than:
            return self.check_expression(value, "<", comparator)
        elif expression==self.__in_between_inclusive:
            return self.check_in_between_inclusive(value, comparator)
        elif expression==self.__in_between:
            return self.check_in_between(value, comparator)
        return jsonify(msg="Something went wrong when Processing Number Criteria")
            
    def number_criteria(self, rowValue):
        for c in self.crisps:
            if self.check_expression_value(rowValue, c.detail[0], c.detail[1]): # If true return Weight Value
                return c.priority
        return jsonify(msg="Something went wrong when Processing Number Criteria")
    
    """
    STRING CRISP TYPE
    For AHP this can be used for substring
    """
    def string_criteria(self, rowValue):
        found = False
        priority = 0
        try:
            for c in self.crisps:
                if c.detail[0].lower().strip() in rowValue.lower() and priority < c.priority:
                    priority = c.priority
                    found = True
            if found is False:
                priority = self.crisps[len(self.crisps)-1].priority
            return priority
        except:
            return jsonify(msg='Something went wrong when Processing Substring Criteria')
    
    def __str__(self):
        return f"name={self.name}, importance={self.importance}"
    

"""
INPUT IMPORTANCE VALUE
Param: List of Criteria, List Of Importance
"""
def input_importance(criterias, importance_list):
    # Pairwise Comparison for each criteria
    inc = 0
    for index in range(len(criterias)-1):
        for i in range(len(criterias)-1-index):
            update_importance(criterias[index], criterias[index+1+i], importance_list[inc])
            inc += 1

def generate_crisp_number(crisp_list, importance_list):
    # Get only the name of the Crisp for each Crisp List
    crisp_name = [a[:1] for a in crisp_list]
    crisp_name = sum(crisp_name, [])

    crisps = []
    for index in range(len(crisp_list)):
        c = AHP_Crisp(name=crisp_list[index][0], details=crisp_list[index][1], criteria_list=crisp_name)
        crisps.append(c)
    input_importance(criterias=crisps, importance_list=importance_list)
    crisps = calculate_priority(crisp_name, crisps)
    return crisps

def generate_crisp_string(crisp_list, importance_list):
    crisps = []
    for index in range(len(crisp_list)):
        c = AHP_Crisp(crisp_list[index], details=[crisp_list[index]], criteria_list=crisp_list)
        crisps.append(c)
    input_importance(criterias=crisps, importance_list=importance_list)
    crisps = calculate_priority(crisp_list, crisps)
    return crisps


""" 
ANALITYCAL HIERARCHY PROCESS METHOD
1. Pair wise comparison for each criteria and crisp
2. Normalize matrix based on result of number one
3. Calculate the sum of normalize value for each row
4. Get the priority value by resul of number 3 divided by number of criteria/crisp
5. Check if consistency ratio is below 0.1 (10%)
6. If false, repeat from number 1
7. Get the alternative priority value by criteria priority value * crisp priority value
8. Sum the total of each row
9. Rank based on the result of number 8
"""

def generate_ahp_result(data_file, criterias_list):
    data = pandas.read_csv(data_file)
    data_truncate = data.drop(columns=[data.columns[0],data.columns[1]], axis=1)
    result_matrix = {}
    criteria_num=0
    for column in data_truncate:
        dm_list = []
        for value in data_truncate[column].values:
            dm_list.append(criterias_list[criteria_num].get_importance_final_value(value))
        d_list = {column:dm_list}
        result_matrix.update(d_list)
        criteria_num += 1

    rm = pandas.DataFrame(data=result_matrix)

    # Calculate Sum of each criteria for each rows
    rm['Total'] = rm.sum(axis=1, numeric_only=True).round(5)

    # Insert again the ID row and identifier row (name or something else)
    rm.insert(0, data.columns.values[0], data[data.columns.values[0]].to_list())
    rm.insert(1, data.columns.values[1], data[data.columns.values[1]].to_list())

    # Rank the result based on total value by Descending order
    rm['Ranking'] = rm['Total'].rank(method='min', ascending=False)

    # Sort DataFrame Ascending by Ranking Columns
    rm = rm.sort_values(by=['Ranking'])
    return(rm)

def get_ahp_max_total_value(criterias):
    max_value = 0
    for criteria in criterias:
        crisp_highest_priority = 0.00
        for crisp in criteria.crisps:
            if crisp.priority > crisp_highest_priority:
                crisp_highest_priority = crisp.priority
        max_value = max_value + criteria.priority * crisp_highest_priority
    return round(max_value, 5)


# # --Uncomment if you want to test it--

# #######################
# # API INPUT SIMULATION
# #######################

# # Get all the criteria name first
# criterias_name = ["Mindset", "Skillset", "Toolset", "Pengalaman"]
# importance_number = [1/5, 3, 1/3, 7, 3, 1/5]

# # Init criteria
# first_c = AHP_Criteria(name="Mindset", crisp_type=0, criteria_list=criterias_name)
# second_c = AHP_Criteria(name="Skillset", crisp_type=1, criteria_list=criterias_name)
# third_c = AHP_Criteria(name="Toolset", crisp_type=1, criteria_list=criterias_name)
# fourth_c = AHP_Criteria(name="Pengalaman", crisp_type=0, criteria_list=criterias_name)

# criterias_list = []
# criterias_list.extend([first_c, second_c, third_c, fourth_c])

# input_importance(criterias=criterias_list, importance_list=importance_number) # Include it in api input
# calculate_priority(criteria_list=criterias_name, criterias=criterias_list) # This one too and so on


# # CRISP FOR EACH CRITERIA

# crisps_list = []

# first_crisp_list = [["First", [2, [85]]], ['Second', [5, [71, 85]]], ['Third', [5, [56, 70]]], ['Fourth', [5, [40, 55]]], ['Fifth', [4, [40]]]]
# importance_number = [3,5,7,9,3,5,7,3,5,3]
# first_crisp = generate_crisp_number(first_crisp_list, importance_number)
# criterias_list[0].update_crisps(first_crisp['criterias'])

# second_crisp_list = ['Teknik Kendaraan Ringan', 'Teknik Listrik', 'Multimedia', 'Tata Boga', 'Kecantikan', 'Tata Busana' ]
# importance_number = [2, 3, 5, 7, 9, 3, 5, 7, 9, 3, 5, 7, 3, 5, 3]
# second_crisp = generate_crisp_string(second_crisp_list, importance_number)
# criterias_list[1].update_crisps(second_crisp['criterias'])

# third_crisp_list = ['Kunci Pas', 'Kunci Inggris', 'Alat Ukur Tekanan Ban', 'Kompresor Udara', 'Solder Listrik', 'Multimeter', 'None']
# importance_number = [2, 3, 5, 6, 7, 9, 2, 4, 5, 6, 8, 3, 5, 6, 8, 2, 3, 5, 2, 4, 3]
# third_crisp = generate_crisp_string(third_crisp_list, importance_number)
# criterias_list[2].update_crisps(third_crisp['criterias'])

# fourth_crisp_list = [["First", [2, [24]]], ['Second', [5, [19, 24]]], ['Third', [5, [12, 18]]], ['Fourth', [5, [6, 12]]], ['Fifth', [4, [6]]]]
# importance_number = [3,5,7,9,3,5,7,3,5,3]
# fourth_crisp = generate_crisp_number(fourth_crisp_list, importance_number)
# criterias_list[3].update_crisps(fourth_crisp['criterias'])

# #######################

# ###############
# # USAGE EXAMPLE
# ###############``
# data_file = 'mini_dummy.csv'
# print(criterias_list[0].priority)
# max_value = get_ahp_max_total_value(criterias=criterias_list)
# result = generate_ahp_result(data_file=data_file, criterias_list=criterias_list)
# result.to_csv('out_ahp.csv')
# print("Max Value={}".format(max_value))


