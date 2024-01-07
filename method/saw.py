import pandas
from flask import jsonify

BENEFIT = 0
COST = 1

class Criteria():
    # Criteria Type
    __number = 0
    __string = 1
    __sub_string = 2
    # Number Criteria Type
    __equals_to = 0
    __more_than_equal = 1
    __more_than = 2
    __less_than_equal = 3
    __less_than = 4
    __in_between_inclusive = 5
    __in_between = 6

    def __init__(self, name, weight, atribute, crisp_type, crisps):
        self.name = name
        self.weight = weight
        self.atribute = atribute
        self.crisp_type = crisp_type
        self.crisps = crisps
    
    def __str__(self):
        return f"name={self.name}, weight={self.weight}, atribute={self.atribute}, crisp_type={self.crisp_type}, crisps={self.crisps}"
    
    def get_weight(self):
        return self.weight
    
    """ 
    CRITERIA PROCESSS FUNCTIONS
    """
    # Process the Row Value Given with this Criteria
    def get_weight_value(self, rowValue):
        return self.check_crisp_type(rowValue)
    
    # Check Criteria Type
    def check_crisp_type(self, rowValue):
        if self.crisp_type == self.__number:
            return self.number_criteria(rowValue)
        elif self.crisp_type == self.__string:
            return self.string_criteria(rowValue)
        elif self.crisp_type == self.__sub_string:
            return self.sub_string_criteria(rowValue)
        else:
            return jsonify(msg="Somthing went wrong when Processing Criteria")
    
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
                return c.weight
        return jsonify(msg="Somthing went wrong when Processing Number Criteria")
    
    """
    STRING CRISP TYPE
    """
    def string_criteria(self, rowValue):
        for c in self.crisps:
            if rowValue.lower() == c.detail[0].lower().strip():
                return c.weight
        return jsonify(msg='Something went wrong when Procesing String Criteria')

    """
    SUB STRING CRISP TYPE
    """
    def sub_string_criteria(self, rowValue):
        weight = 1
        try:
            for c in self.crisps:
                if c.detail[0].lower().strip() in rowValue.lower() and weight < c.weight:
                    weight = c.weight
            return weight
        except:
            return jsonify(msg='Something went wrong when Processing Substring Criteria')
    
    """ 
    MAKE NORMALIZATION MATRIX 
    CONSIDERING COST/BENEFIT 
    """
    def normalize_value_benefit_or_cost(self, rowValue, minValue, maxValue):
        if self.atribute == BENEFIT:
            return rowValue/maxValue
        elif self.atribute == COST:
            return minValue/rowValue
        else:
            return jsonify(msg='Something went wrong when Normalizing Matrix')
        
    """
    CALCULATE WEIGHT RESULT
    """
    def calculate_weight_result(self, rowValue):
        return rowValue*self.weight
        
class Crisp():
    def __init__(self, detail, weight):
        self.detail = detail
        self.weight = weight
    
    def __str__(self):
        return f"detail={self.detail}, weight={self.weight}"



""" 
SIMPLE ADDITIVE WEIGHT METOD
1. Make Decision matrix
2. Calculate Normalization Matrix based on Criteria Atribute
3. Calculate Weight * Normalization Value for each row
4. Calculate Sum of each row
5. Rank based on the total value on number 4
"""
def generate_saw_result(data_file, criterias):
    data = pandas.read_csv(data_file)
    data_truncate = data.drop(columns=[data.columns[0],data.columns[1]], axis=1)
    decision_matrix = {}
    criteria_num=0
    for column in data_truncate:
        dm_list = []
        for value in data_truncate[column].values:
            dm_list.append(criterias[criteria_num].get_weight_value(value))
        d_list = {column:dm_list}
        decision_matrix.update(d_list)
        criteria_num += 1

    dm = pandas.DataFrame(data=decision_matrix)
    
    # Get Max and Min Value for each columns that will be used for Normalization Matrix
    max_value = dm.max()
    min_value = dm.min()

    # Calculate Normalization Matrix
    normalization_matrix = {}
    criteria_num = 0
    for column in dm:
        nm_list = []
        for value in dm[column].values:
            nm_list.append(criterias[criteria_num].normalize_value_benefit_or_cost(value, min_value[column], max_value[column]))
        n_list = {column:nm_list}
        normalization_matrix.update(n_list)
        criteria_num += 1

    nm = pandas.DataFrame(data=normalization_matrix)

    # Calculate Weight * Normalization Value for each row
    result_m = nm
    criteria_num = 0
    for column in result_m:
        for index in result_m.index:
            result_m.loc[index, column] = criterias[criteria_num].calculate_weight_result(result_m.loc[index, column])
        criteria_num += 1

    # Calculate Sum of each criteria for each rows
    result_m['Total'] = result_m.sum(axis=1, numeric_only=True)

    # Insert again the ID row and identifier row (name or something else)
    result_m.insert(0, data.columns.values[0], data[data.columns.values[0]].to_list())
    result_m.insert(1, data.columns.values[1], data[data.columns.values[1]].to_list())

    # Rank the result based on total value by Descending order
    result_m['Ranking'] = result_m['Total'].rank(method='min', ascending=False)

    # Sort DataFrame Ascending by Ranking Columns
    result_m = result_m.sort_values(by=['Ranking'])
    return result_m

def get_saw_max_total_value(criterias):
    max_value = 0
    for c in criterias:
        max_value += c.get_weight()
    return max_value


# # --Uncomment if you want to test it--

# #######################
# # API INPUT SIMULATION
# #######################


# # First Criteria
# first_crisp = Crisp(detail=[2, [80]], weight=3)
# second_crisp = Crisp(detail=[5, [40,80]], weight=2)
# third_crisp = Crisp(detail=[4, [40]], weight=1)
# crisps = []
# crisps.extend([first_crisp, second_crisp, third_crisp])

# first_c = Criteria(
#     name="Mindset", weight=30, atribute=BENEFIT, crisp_type=0, crisps=crisps
# )

# # Second Criteria
# first_crisp = Crisp(detail=["Kecantikan"], weight=6)
# second_crisp = Crisp(detail=["Tata Busana"], weight=5)
# third_crisp= Crisp(detail=["Multimedia"], weight=4)
# fourth_crisp = Crisp(detail=["Tata Boga"], weight=3)
# fifth_crisp= Crisp(detail=["Teknik Listrik"], weight=2)
# sixth_crisp = Crisp(detail=["Teknik Kendaraan Ringan"], weight=1)
# crisps = []
# crisps.extend([first_crisp, second_crisp, third_crisp, fourth_crisp, fifth_crisp, sixth_crisp])

# second_c = Criteria(
#     name="Skillset", weight=50, atribute=BENEFIT, crisp_type=1, crisps=crisps
# )

# # Third Criteria
# first_crisp = Crisp(detail=["Foundation"], weight=7)
# second_crisp = Crisp(detail=["Body Painting"], weight=6)
# third_crisp= Crisp(detail=["Mascara"], weight=5)
# fourth_crisp = Crisp(detail=["Coreldraw"], weight=4)
# fifth_crisp= Crisp(detail=["Kamera"], weight=3)
# sixth_crisp = Crisp(detail=["Mesin Jahit"], weight=2)
# crisps = []
# crisps.extend([first_crisp, second_crisp, third_crisp, fourth_crisp, fifth_crisp, sixth_crisp])

# third_c = Criteria(
#     name="Toolset", weight=20, atribute=BENEFIT, crisp_type=2, crisps=crisps
# )

# # Fourth Criteria
# first_crisp = Crisp(detail=[2, [24]], weight=3)
# second_crisp = Crisp(detail=[5, [12,24]], weight=2)
# third_crisp = Crisp(detail=[4, [12]], weight=1)
# crisps = []
# crisps.extend([first_crisp, second_crisp, third_crisp])

# fourth_c = Criteria(
#     name="Mindset", weight=40, atribute=BENEFIT, crisp_type=0, crisps=crisps
# )

# #######################

# ###############
# # USAGE EXAMPLE
# ###############

# data_file = 'mini_dummy.csv'
# criterias = []
# criterias.extend([first_c, second_c, third_c, fourth_c])
# result = generate_saw_result(data_file=data_file, criterias=criterias)
# max_value = get_saw_max_total_value(criterias=criterias)
# result.to_csv('out1.csv')
# print("Max Value={}".format(max_value))
