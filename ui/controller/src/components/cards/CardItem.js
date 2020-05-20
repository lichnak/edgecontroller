// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import withStyles from '@material-ui/core/styles/withStyles';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import Avatar from '@material-ui/core/Avatar';
import DescriptionIcon from '@material-ui/icons/Description';
import ApiClient from '../../api/ApiClient';
import ButtonBar from '../buttons/ButtonBar';
import Grid from '@material-ui/core/Grid';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogTitle from '@material-ui/core/DialogTitle';
import Button from '@material-ui/core/Button';
import CircularProgress from '@material-ui/core/CircularProgress';
import Slide from '@material-ui/core/Slide';
import { withSnackbar } from 'notistack';

const styles = theme => ({
  root: {
    marginBottom: '8px',
  },
  paper: {
    padding: theme.spacing(3),
    textAlign: 'left',
    color: theme.palette.text.secondary
  },
  avatar: {
    margin: 10,
    backgroundColor: theme.palette.grey['200'],
    color: theme.palette.text.primary,
  },
  avatarContainer: {
    [theme.breakpoints.down('sm')]: {
      marginLeft: 0,
      marginBottom: theme.spacing(4)
    }
  },
  itemContainer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'flex-start',
    [theme.breakpoints.down('sm')]: {
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center'
    }
  },
  baseline: {
    alignSelf: 'baseline',
    marginLeft: theme.spacing(4),
    flexGrow: 1,
    [theme.breakpoints.down('sm')]: {
      display: 'flex',
      flexDirection: 'column',
      textAlign: 'center',
      alignItems: 'center',
      width: '100%',
      marginTop: theme.spacing(2),
      marginBottom: theme.spacing(2),
      marginLeft: 0
    }
  },
  inline: {
    display: 'inline-block',
    marginLeft: theme.spacing(2),
    [theme.breakpoints.down('sm')]: {
      marginLeft: 0
    }
  },
  inlineRight: {
    display: 'flex',
    height: '100px',
    width: '225px',
    justifyContent: 'flex-end',
    alignItems: 'flex-end',
    [theme.breakpoints.down('sm')]: {
      width: '100%',
      margin: 0,
      textAlign: 'center'
    }
  },
  backButton: {
    marginRight: theme.spacing(2)
  },
});

class CardItem extends Component {

  constructor(props) {
    super(props);

    this.state = {
      deleted: false,
      dialogShown: false,
      url: `${this.props.resourcePath}/${this.props.CardItem.id}`
    };

    this.handleDelete = this.handleDelete.bind(this);
  }

  handleDelete = () => {
    this.setState({ dialogShown: true });
  };

  handleClose = () => {
    this.setState({ dialogShown: false });
  };

  handleDeleteReq = () => {
    if (this.state.showLoader === true) {
      return;
    }

    this.setState({ showLoader: true });

    ApiClient.delete(this.state.url)
      .then(() => {
        this.setState({ deleted: true });
        this.handleClose();
      })
      .catch((err) => {
        this.props.enqueueSnackbar(`${err.toString()}. Please try again later.`, {
          variant: 'error',
        });
        this.setState({ showLoader: false });
        setTimeout(this.props.closeSnackbar, 2000);
        this.handleClose();
      });
  };


  render() {
    const { classes, CardItem, excludeKeys } = this.props;
    const secondaryLink = (props) => <Link to={this.state.url} {...props} />;
    const filterKey = (key) => {
      return excludeKeys.includes(key) ? null : key;
    };

    const displayCardData = () => {
      return Object.keys(CardItem).filter(filterKey).map(key => {
        return (
          <Grid key={key} item className={classes.inline}>
            <Typography style={{ textTransform: 'uppercase' }} color='secondary' gutterBottom>
              {key}
            </Typography>
            <Typography variant="h6" gutterBottom>
              {CardItem[key]}
            </Typography>
          </Grid>
        )
      })
    };

    const cardItem = () => (
      <div className={classes.root}>
        <Slide direction="right" in={!this.state.deleted} timeout={500} unmountOnExit>
          <Paper className={classes.paper}>
            <div className={classes.itemContainer}>
              <div className={classes.avatarContainer}>
                <Avatar className={classes.avatar}>
                  <DescriptionIcon />
                </Avatar>
              </div>
              <div className={classes.baseline}>
                <Grid container wrap="nowrap" direction="row" justify="space-between" alignItems="flex-start">
                  {displayCardData()}
                </Grid>
              </div>

              <div className={classes.inlineRight}>
                <ButtonBar
                  className={classes.buttonBar}
                  primaryButtonName="Delete"
                  primaryButtonAction={this.handleDelete}
                  secondaryButtonName="Edit"
                  secondaryLink={secondaryLink} />
              </div>
            </div>
          </Paper>
        </Slide>
        <Dialog
          open={this.state.dialogShown}
          onClose={this.handleClose}
          aria-labelledby="alert-dialog-title"
          aria-describedby="alert-dialog-description"
        >
          <DialogTitle id="alert-dialog-title">{`Delete: ${CardItem.id} ?`}</DialogTitle>
          <DialogContent>
            <DialogContentText id="alert-dialog-description">
              {this.props.dialogText}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            {this.state.showLoader ? (<CircularProgress />) : ""}
            <Button onClick={this.handleClose} color="primary">
              Cancel
            </Button>
            <Button onClick={this.handleDeleteReq} color="primary" autoFocus>
              Delete
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );

    return (
      cardItem()
    );
  }
}

export default withSnackbar(withStyles(styles)(CardItem));
