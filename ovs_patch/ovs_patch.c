/*
 * Author: Shubham Tiwari - support for qdisc stats
 */ 

/* Add this function and prototype to netdev-linux.c */


static int 
default_qdisc_dump_stats(const struct netdev *netdev OVS_UNUSED, 
                         const struct ofpbuf *nlmsg, 
                         netdev_dump_queue_stats_cb *cb, void *aux) {

    /* cast netdev into netdev_linux to obtain all the info */
    /* struct netdev_linux *netdev_ = netdev_linux_cast(netdev); */

    if (nlmsg!=NULL) {
        /* Do nothing, place holder */
    }
    struct ofpbuf request, qdisc;

    /* const struct tc_ops *ops; */
    struct tcmsg *tcmsg;
    struct netdev_queue_stats stats;
    /* unsigned int handle, major, minor; */
    /* int error, parse_error; */ 

    /* TODO: parse stats and make a callback
       https://mail.openvswitch.org/pipermail/ovs-dev/2015-March/295937.html
       NLM_F_REQUEST flag on RTM_GETQDISC returns no reply from kernel (bug).
       A workaround is to use the flag NLM_F_DUMP, which dumps all the qdiscs.
       We then need to filter out the qdisc for the interface that we need. 
    
       One way is to use netdev->name and compare
       it with the port in the reply, and make a callback
       with only the relevent reply.
    */

    tcmsg = netdev_linux_tc_make_request(netdev, RTM_GETQDISC, NLM_F_DUMP,
                                         &request);

    /* 
     * Important, switches themselves also have struct netdev allocated to them.
     * While looping through ports, struct netdev of the switch with netdev->name ="s1"
     * for example, also gets looped through (for some reason ovs developers included 
     * that as a port!). That situation has to be avoided, since it results no reply
     * while transaction, and ultimately segmentation fault (!). 
     */      

    if (!tcmsg) {
        return ENODEV;
    }                                                                     

    tcmsg->tcm_parent = 0;
    /* tc_transact(&request, &qdisc); */
    /* Iterate the through the messages using dumps */
    struct queue_dump_state state_;
    struct queue_dump_state *state = &state_;
    nl_dump_start(&state->dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);
    ofpbuf_init(&state->buf, NL_DUMP_BUFSIZE);

    while (nl_dump_next(&state_.dump, &qdisc, &state_.buf)) {
        /* Parse the message */
        /* Parse the stats in buffer qdisc */

        /* Determine the ifindex and match it with netdev */
        int ifindex;
        int error;

        error = get_ifindex(netdev, &ifindex);
        if (error) {
            return -1;
        }
        struct tcmsg *tc = ofpbuf_at_assert(&qdisc, NLMSG_HDRLEN, sizeof *tc);
        if (tc->tcm_ifindex != ifindex)
            continue;

        static const struct nl_policy tca_policy[] = {
            [TCA_OPTIONS] = { .type = NL_A_NESTED, .optional = false },
            [TCA_STATS2] = { .type = NL_A_NESTED, .optional = false },
        };

        struct nlattr *ta[ARRAY_SIZE(tca_policy)];

        if (!nl_policy_parse(&qdisc, NLMSG_HDRLEN + sizeof(struct tcmsg),
                            tca_policy, ta, ARRAY_SIZE(ta))) {
            VLOG_WARN_RL(&rl, "failed to parse qdisc message");
            goto error;
        }

        const struct gnet_stats_queue *gsq;
        struct gnet_stats_basic gsb;

        static const struct nl_policy stats_policy[] = {
            [TCA_STATS_BASIC] = { .type = NL_A_UNSPEC, .optional = false,
                                    .min_len = sizeof gsb },
            [TCA_STATS_QUEUE] = { .type = NL_A_UNSPEC, .optional = false,
                                    .min_len = sizeof *gsq },
        };
        struct nlattr *sa[ARRAY_SIZE(stats_policy)];

        if (!nl_parse_nested(ta[TCA_STATS2], stats_policy,
                                sa, ARRAY_SIZE(sa))) {
            VLOG_WARN_RL(&rl, "failed to parse class stats");
            goto error; 
        }

        /* Alignment issues screw up the length of struct gnet_stats_basic on
            * some arch/bitsize combinations.  Newer versions of Linux have a
            * struct gnet_stats_basic_packed, but we can't depend on that.  The
            * easiest thing to do is just to make a copy. */
        memset(&gsb, 0, sizeof gsb);
        memcpy(&gsb, nl_attr_get(sa[TCA_STATS_BASIC]),
                MIN(nl_attr_get_size(sa[TCA_STATS_BASIC]), sizeof gsb));
        stats.tx_bytes = gsb.bytes;
        stats.tx_packets = gsb.packets;

        gsq = nl_attr_get(sa[TCA_STATS_QUEUE]);
        stats.tx_errors = gsq->drops;
        stats.qlen = gsq->qlen;
        stats.created = 0;
        /* Make callback */
        (*cb)(0, &stats, aux);
    }

    finish_queue_dump(&state_);
    return 1;

    error:
    return -1;
}


/* Modify the following struct, copy and paste this version on top of the existing one */

static const struct tc_ops tc_ops_default = {
    .ovs_name = "",                         /* ovs_name */
    .tc_install = default_tc_install,
    .tc_load = default_tc_load,
    .n_queues = 5,
    .class_dump_stats = default_qdisc_dump_stats,
};

/* Modify the following function, copy and paste this version on top of the existing version */

static int
netdev_linux_dump_queue_stats(const struct netdev *netdev_,
                              netdev_dump_queue_stats_cb *cb, void *aux)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);
    if (netdev_linux_netnsid_is_remote(netdev)) {
        error = EOPNOTSUPP;
        goto exit;
    }

    error = tc_query_qdisc(netdev_);
    if (!error) {
        struct queue_dump_state state;

        if (!netdev->tc->ops->class_dump_stats) {
            error = EOPNOTSUPP;
        } else if (strcmp(netdev->tc->ops->ovs_name, "")==0) {
            netdev->tc->ops->class_dump_stats(netdev_, NULL, cb, aux);
        } else if (!start_queue_dump(netdev_, &state)) {
            error = ENODEV;
        } else {
            struct ofpbuf msg;
            int retval;

            while (nl_dump_next(&state.dump, &msg, &state.buf)) {
                retval = netdev->tc->ops->class_dump_stats(netdev_, &msg,
                                                           cb, aux);
                if (retval) {
                    error = retval;
                }
            }

            retval = finish_queue_dump(&state);
            if (retval) {
                error = retval;
            }
        }
    }

exit:
    ovs_mutex_unlock(&netdev->mutex);
    return error;
}