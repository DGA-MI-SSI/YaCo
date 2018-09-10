//  Copyright (C) 2017 The YaCo Authors
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "Git.hpp"

#include "Helpers.h"
#include "Yatools.hpp"

#include <future>

#if 1
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("async", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

#include "Bench.h"

namespace
{
    template<typename T>
    struct command_queue
    {
        command_queue()
            : started_(false)
        {
        }

        void start()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            started_ = true;
        }

        bool started()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return started_;
        }

        void stop()
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                started_ = false;
            }
            condition_.notify_one();
        }

        void post(T&& cmd)
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                queue_.push_back(std::move(cmd));
            }
            condition_.notify_one();
        }

        bool wait(std::vector<T>& items)
        {
            items.clear();
            std::unique_lock<std::mutex> lock(mutex_);
            condition_.wait(lock, [&]
            {
                return !started_ || !queue_.empty();
            });
            items.swap(queue_);
            return !items.empty();
        }

        std::mutex              mutex_;
        std::condition_variable condition_;
        std::vector<T>          queue_;
        bool                    started_;
    };

    struct worker
    {
        using value_type = std::function<void(void)>;

        struct item_type
        {
            item_type(const value_type& cmd, std::promise<void>&& promise)
                : cmd(cmd)
                , promise(std::move(promise))
            {
            }

            value_type          cmd;
            std::promise<void>  promise;
        };

        ~worker()
        {
            if(queue_.started())
                stop();
        }

        void start()
        {
            queue_.start();
            thread_ = std::thread(&worker::run, this);
        }

        void stop()
        {
            queue_.stop();
            thread_.join();
        }

        std::future<void> post(const value_type& cmd)
        {
            std::promise<void> promise;
            auto future = promise.get_future();
            queue_.post({cmd, std::move(promise)});
            return future;
        }

        void run()
        {
            std::vector<item_type> jobs;
            while(queue_.wait(jobs))
                for(auto& job : jobs)
                {
                    job.cmd();
                    job.promise.set_value();
                }
        }

        std::thread                 thread_;
        command_queue<item_type>    queue_;
    };

    struct GitAsync
        : public IGit
    {
         GitAsync(std::shared_ptr<IGit> git);
        ~GitAsync();

        // IGit methods
        bool        add_remote          (const std::string& name, const std::string& url) override;
        bool        fetch               (const std::string& name) override;
        bool        clone               (const std::string& path, ECloneMode emode) override;
        bool        add_file            (const std::string& name) override;
        bool        remove_file         (const std::string& name) override;
        std::string config_get_string   (const std::string& name) override;
        bool        config_set_string   (const std::string& name, const std::string& value) override;
        bool        diff_index          (const std::string& from, const on_blob_fn& on_blob) override;
        bool        rebase              (const std::string& upstream, const std::string& dst, IPatcher& patcher, const on_fixup_fn& on_fixup, const on_conflict_fn& on_conflict) override;
        bool        commit              (const std::string& message) override;
        bool        checkout_head       () override;
        bool        is_tracked          (const std::string& name) override;
        std::string get_commit          (const std::string& name) override;
        bool        push                (const std::string& src, const std::string& remote, const std::string& dst) override;
        bool        remotes             (const on_remote_fn& on_remote) override;
        bool        status              (const std::string& path, const on_status_fn& on_path) override;
        void        flush               () override;

        std::shared_ptr<IGit>   git_;
        worker                  worker_;
    };

    namespace
    {
        struct Flusher
        {
            Flusher(GitAsync& async)
                : async(async)
            {
                async.flush();
            }

            ~Flusher()
            {
                async.git_->flush();
            }

            GitAsync& async;
        };
    }
}

std::shared_ptr<IGit> MakeGitAsync(const std::string& path)
{
    auto git = MakeGit(path);
    if(!git)
        return std::nullptr_t();

    return std::make_shared<GitAsync>(git);
}

GitAsync::GitAsync(std::shared_ptr<IGit> git)
    : git_(git)
{
    worker_.start();
}

GitAsync::~GitAsync()
{
    worker_.stop();
}

bool GitAsync::add_remote(const std::string& name, const std::string& url)
{
    return git_->add_remote(name, url);
}

bool GitAsync::fetch(const std::string& name)
{
    const auto flusher = Flusher{*this};
    return git_->fetch(name);
}

bool GitAsync::clone(const std::string& path, ECloneMode emode)
{
    const auto flusher = Flusher{*this};
    return git_->clone(path, emode);
}

bool GitAsync::add_file(const std::string& name)
{
    const auto flusher = Flusher{*this};
    return git_->add_file(name);
}

bool GitAsync::remove_file(const std::string& name)
{
    const auto flusher = Flusher{*this};
    return git_->remove_file(name);
}

std::string GitAsync::config_get_string(const std::string& name)
{
    const auto flusher = Flusher{*this};
    return git_->config_get_string(name);
}

bool GitAsync::config_set_string(const std::string& name, const std::string& value)
{
    const auto flusher = Flusher{*this};
    return git_->config_set_string(name, value);
}

bool GitAsync::diff_index(const std::string& from, const on_blob_fn& on_blob)
{
    const auto flusher = Flusher{*this};
    return git_->diff_index(from, on_blob);
}

bool GitAsync::rebase(const std::string& upstream, const std::string& dst, IPatcher& patcher, const on_fixup_fn& on_fixup, const on_conflict_fn& on_conflict)
{
    const auto flusher = Flusher{*this};
    return git_->rebase(upstream, dst, patcher, on_fixup, on_conflict);
}

bool GitAsync::commit(const std::string& message)
{
    const auto flusher = Flusher{*this};
    return git_->commit(message);
}

bool GitAsync::checkout_head()
{
    const auto flusher = Flusher{*this};
    return git_->checkout_head();
}

bool GitAsync::is_tracked(const std::string& name)
{
    return git_->is_tracked(name);
}

std::string GitAsync::get_commit(const std::string& name)
{
    const auto flusher = Flusher{*this};
    return git_->get_commit(name);
}

bool GitAsync::push(const std::string& src, const std::string& remote, const std::string& dst)
{
    worker_.post([=]
    {
        git_->push(src, remote, dst);
    });
    return true;
}

bool GitAsync::remotes(const on_remote_fn& on_remote)
{
    const auto flusher = Flusher{*this};
    return git_->remotes(on_remote);
}

bool GitAsync::status(const std::string& path, const on_status_fn& on_path)
{
    const auto flusher = Flusher{*this};
    return git_->status(path, on_path);
}

void GitAsync::flush()
{
    worker_.post([]{}).wait();
    git_->flush();
}
