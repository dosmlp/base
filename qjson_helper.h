#ifndef QJSONHELPER_H
#define QJSONHELPER_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QJsonArray>
#include <QList>
namespace QJsonHelper {
template<class T>
void fromJson(const QJsonValue &j, QList<T> &p)
{
    if (j.isArray()) {
        QJsonArray arr = j.toArray();
        p.resize(arr.size());
        for (int i = 0;i < arr.size();++i) {
            const QJsonValue& v = arr.at(i);
            p[i].fromJson(v);
        }
    }
}
template<class T>
QJsonValue toJson(const QList<T> &p)
{
    QJsonArray arr;
    for (const T& t:p) {
        arr.append(t.toJson());
    }
    return arr;
}

template <typename>
constexpr bool is_list = false;

template <typename... Args>
constexpr bool is_list<QList<Args...>> = true;

template<class T1>
void get(const QJsonValue& j, T1& p)
{
    if constexpr(is_list<T1>) {
        fromJson(j,p);
    } else {
        p.fromJson(j);
    }

}

template<class T1>
QJsonValue to(T1& p)
{
    if constexpr(is_list<T1>) {
        return toJson(p);
    } else {
        return p.toJson();
    }

}

}

#endif // QJSONHELPER_H
