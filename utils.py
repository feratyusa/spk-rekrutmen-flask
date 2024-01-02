from json import loads, dumps
import pandas

def drop_rows_based_on_threshold(file_path, max_value, threshold_percentage):
    threshold_value = (threshold_percentage/100) * max_value
    print(threshold_value)
    data = pandas.read_csv(file_path)
    data.drop(data[data['Total'] < threshold_value].index, inplace=True)
    return data

# # # Utilities Test
# data = drop_rows_based_on_threshold("./method/out1.csv", 140, 50)
# print(data)
# result = data.to_json(orient='split')
# parsed = loads(result)
# print(parsed)