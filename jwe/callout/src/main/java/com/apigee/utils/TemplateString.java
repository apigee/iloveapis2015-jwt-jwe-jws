package com.apigee.utils;

import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/*
 * TemplateString
 *
 * This class is used to convert a string in which curly-braces denote
 * variables to be replaced, into a form that uses ${xxx}, which is
 * required by the StrSubstitutor class which is part of Apache
 * commons.lang.
 *
 * It is used by Edge callout classes to read and "resolve" property
 * values that may contain multiple variable references , or variable
 * references surrounded by other text, or both.
 *
 */
public class TemplateString {
    private final Pattern tmpltPattern =
        Pattern.compile("\\{([^\\}]+)\\}", Pattern.CASE_INSENSITIVE);
    public ArrayList<String> variableNames;
    public String template;
    private void injectDollar(int position) {
        template =
            template.substring(0, position) +
            "$" + template.substring(position, template.length());
    }
    public TemplateString(String s) {
        this.variableNames = new ArrayList<String>();
        examineString(s);
    }

    private void examineString(String input) {
        this.template = input;
        int x = 0;
        Matcher m = tmpltPattern.matcher(input);
        while (m.find()) {
            variableNames.add(m.group(1));
            injectDollar(m.start() + x++);
        }
    }
}
