int secondsSinceEpoch(DateTime dateTime) =>
    (dateTime.millisecondsSinceEpoch / 1000).floor();
