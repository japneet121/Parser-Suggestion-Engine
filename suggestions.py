from fields import get_field_suggestions
from factors import get_factor_suggestion,get_factors_df
from parsers import get_parser_suggestion_html

def get_suggestions(input_dict):
    suggested_fields=get_field_suggestions(input_dict)
    suggested_factors=get_factors_df(input_dict)
    suggested_parsers=get_parser_suggestion_html(input_dict)
    return(suggested_fields,suggested_factors,suggested_parsers)