export function lowerCaseFieldNames(object: any) {
    if(!object) return;

    for (var key in object) {
        var value = object[key];
        var lowerKey = key.toLowerCase();
        if (key !== lowerKey) {
            object[lowerKey] = value;
            delete object[key];
        }
    }
}