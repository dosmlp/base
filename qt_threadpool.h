#ifndef QT_THREADPOOL_H
#define QT_THREADPOOL_H

#include <QObject>
#include <QPointer>
#include <QThreadPool>
//示例 QPointer可以在包裹的qobject对象被删除后自动置空，确保回调对象的生命周期被正确识别
/*
QWidget* widget = new QWidget;
QPointer<QWidget> ptr(widget);
ThreadPool::invokeAsync([ptr]{
    QThread::sleep(1000);
    invoke([ptr]{
        if (!ptr) return;
        ptr->setWindowTitle("threadpool");
    });
});
*/

class ThreadPool : public QObject
{
public:
    using task = std::function<void ()>;
    ~ThreadPool()
    {
        async_worker_->clear();
        async_worker_->waitForDone();
    }
    //在qt事件循环中调用
    template <typename Func>
    static void invoke(Func &&func)
    {
        instance()->_invoke(std::forward<Func>(func));
    }

    static void invokeAsync(task&& func)
    {
        instance()->_invokeAsync(std::move(func));
    }
    static ThreadPool* instance()
    {
        static ThreadPool t;
        return &t;
    }
private:
    ThreadPool(QObject* parent = nullptr):QObject(parent),async_worker_(new QThreadPool(this))
    {
        async_worker_->setMaxThreadCount(QThread::idealThreadCount());
    }
    template <typename Func>
    void _invoke(Func &&func)
    {
        QMetaObject::invokeMethod(this, std::forward<Func>(func), Qt::QueuedConnection);
    }

    void _invokeAsync(task&& func)
    {
        async_worker_->start(std::forward<task>(func));
    }
    QThreadPool* async_worker_;
}

#endif // QT_THREADPOOL_H
